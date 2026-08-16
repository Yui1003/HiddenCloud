const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const path = require('path');
const webpush = require('web-push');

const PORT = Number(process.env.PORT || 5000);
const API_URL = 'https://static.ninjasaga.cc/data/clan_rankings.json';
const POLL_INTERVAL_MS = 5000;
const MEMBERSHIP_PURGE_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const HIDDEN_CLOUD_CLAN_ID = 777;
const POSSIBLE_BLEEDING_CLAN_THRESHOLD = 2;
const POSSIBLE_BLEEDING_DELAY_MS = 10000;
const DATA_DIR = process.env.PUSH_DATA_DIR || path.join(__dirname, '.data');
const SUBSCRIPTIONS_FILE = path.join(DATA_DIR, 'push-subscriptions.json'); // local fallback
const DETECTOR_STATE_FILE = path.join(DATA_DIR, 'push-detector-state.json');
const FIREBASE_TOKEN_FILE = path.join(DATA_DIR, 'firebase-token.json');
const WEEKLY_GAINS_FILE         = path.join(DATA_DIR, 'weekly-gains-state.json');
const DISCORD_WEBHOOK_CACHE_FILE = path.join(DATA_DIR, 'discord-webhook-cache.json');

const DISCORD_WEBHOOK_CACHE_TTL_MS = 60 * 60_000;  // 1 hour
const WEEKLY_GAINS_SYNC_INTERVAL_MS = 5 * 60_000;  // Write weeklyGains/777 at most every 5 min
const WEEKLY_GAINS_RESTORE_RETRY_MS = 60_000;       // Retry a failed baseline restore
const CONFIRMED_BLEEDS_FALLBACK_POLL_MS = 30_000;  // Re-read confirmedBleeds every 30 s as fallback
const WEEK_MS = 7 * 24 * 60 * 60 * 1000;           // one weekly-gains cut = 7 days

// One-time migration anchor: the season live as of this deploy started at
// Aug 16, 2026, 1:00 PM PH time (PH = UTC+8, so 05:00 UTC). Auto-detecting a
// season's start (from when its season.id first appears on a poll) only
// works going forward, so this hardcoded value seeds the *current* season's
// true start precisely instead of using "whenever this code first deploys"
// (which would shift every weekly cut later by however many hours/days late
// the deploy happens to land — whether that's the very first poll after
// deploy, or a season rollover the old code already saw and recorded without
// a precise start). Bounded to ~5 weeks past that date so it can never
// accidentally apply to a later season once real time has moved on; every
// season after this one is anchored automatically (from its own rollover
// poll) same as before.
const KNOWN_CURRENT_SEASON_START_MS = Date.UTC(2026, 7, 16, 5, 0, 0);
const KNOWN_ANCHOR_VALID_UNTIL_MS   = KNOWN_CURRENT_SEASON_START_MS + 35 * 24 * 60 * 60 * 1000;

// Picks the precise start of the season currently being (re)anchored. Uses
// the hardcoded known start while we're still within its validity window
// (covers both a fresh/migrating state and the rollover poll that first
// notices this season began), otherwise falls back to "now" — accurate to
// one poll cycle (~5s) for any season after this one.
function resolveSeasonStartTs(now, seasonEndTs) {
  if (now < KNOWN_ANCHOR_VALID_UNTIL_MS && KNOWN_CURRENT_SEASON_START_MS < seasonEndTs) {
    return KNOWN_CURRENT_SEASON_START_MS;
  }
  return now;
}

// Given a resolved season start, figures out which weekly block "now" falls
// into and returns a freshly-seeded state for it. Used both when a season
// rollover is first detected and when migrating/starting fresh mid-season
// (e.g. this deploy landing hours after the real 1PM PH reset already
// happened) — either way "now" may already be into week 2+.
function seedSeasonState(seasonId, seasonEndTs, now) {
  const seasonStartTs = resolveSeasonStartTs(now, seasonEndTs);
  const elapsed   = Math.max(0, now - seasonStartTs);
  const weekIndex = Math.floor(elapsed / WEEK_MS) + 1;
  const weekStartTs = seasonStartTs + (weekIndex - 1) * WEEK_MS;
  const next = startNewWeek(seasonId, seasonEndTs, weekStartTs, weekIndex);
  next.seasonStartTs = seasonStartTs;
  return next;
}

// Firebase project config (same project the client already uses)
const FIREBASE_API_KEY = process.env.FIREBASE_API_KEY;
if (!FIREBASE_API_KEY) throw new Error('FIREBASE_API_KEY environment variable is not set.');
const FIREBASE_PROJECT = 'clantracker-22435';
const FIRESTORE_BASE =
  `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT}/databases/(default)/documents`;
const FIREBASE_AUTH_URL =
  `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${FIREBASE_API_KEY}`;
const FIREBASE_REFRESH_URL =
  `https://securetoken.googleapis.com/v1/token?key=${FIREBASE_API_KEY}`;

fs.mkdirSync(DATA_DIR, { recursive: true });

// ── Helpers ──────────────────────────────────────────────────────────────────

// Convert a plain JS value to a Firestore REST API typed value.
function fsValue(val) {
  if (val === null || val === undefined) return { nullValue: null };
  if (typeof val === 'boolean') return { booleanValue: val };
  if (typeof val === 'number') {
    return Number.isInteger(val) ? { integerValue: String(val) } : { doubleValue: val };
  }
  if (typeof val === 'string') return { stringValue: val };
  if (Array.isArray(val)) return { arrayValue: { values: val.map(fsValue) } };
  if (typeof val === 'object') {
    const fields = {};
    for (const [k, v] of Object.entries(val)) fields[k] = fsValue(v);
    return { mapValue: { fields } };
  }
  return { stringValue: String(val) };
}

// Wrap a plain JS object as a Firestore REST document body { fields: { … } }.
function fsDoc(obj) {
  const fields = {};
  for (const [k, v] of Object.entries(obj)) fields[k] = fsValue(v);
  return { fields };
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (_) {
    return fallback;
  }
}

function writeJson(file, value) {
  const temp = `${file}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(value, null, 2));
  fs.renameSync(temp, file);
}

// ── VAPID ─────────────────────────────────────────────────────────────────────

function base64Url(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  return Buffer.from(padded, 'base64');
}

function deriveVapidPublicKey(privateKey) {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(fromBase64Url(privateKey));
  return base64Url(ecdh.getPublicKey(null, 'uncompressed'));
}

function loadVapidKeys() {
  const configuredKeys = readJson(path.join(DATA_DIR, 'vapid-keys.json'), null);
  if (process.env.VAPID_PRIVATE_KEY) {
    return {
      privateKey: process.env.VAPID_PRIVATE_KEY,
      publicKey: process.env.VAPID_PUBLIC_KEY || deriveVapidPublicKey(process.env.VAPID_PRIVATE_KEY),
    };
  }
  if (configuredKeys?.privateKey && configuredKeys?.publicKey) return configuredKeys;

  // Derive a stable pair from the existing server secret so subscriptions
  // survive restarts and fresh deployments without exposing the secret.
  const seed = process.env.SESSION_SECRET || 'hidden-cloud-development-only';
  const privateKey = base64Url(crypto.createHash('sha256')
    .update(`${seed}:hidden-cloud-vapid`)
    .digest());
  return { privateKey, publicKey: deriveVapidPublicKey(privateKey) };
}

const { privateKey, publicKey } = loadVapidKeys();
webpush.setVapidDetails(
  process.env.VAPID_SUBJECT || 'https://hiddencloud.onrender.com',
  publicKey,
  privateKey
);

// ── Firebase Auth (anonymous sign-in for Firestore access) ───────────────────

let _fbIdToken = null;
let _fbRefreshToken = readJson(FIREBASE_TOKEN_FILE, {}).refreshToken || null;
let _fbTokenExpiry = 0;

async function getFirebaseToken() {
  const now = Date.now();
  // Return cached token if still valid (with 60s buffer)
  if (_fbIdToken && now < _fbTokenExpiry - 60_000) return _fbIdToken;

  // Try refreshing with the saved refresh token first
  if (_fbRefreshToken) {
    try {
      const res = await fetch(FIREBASE_REFRESH_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grant_type: 'refresh_token', refresh_token: _fbRefreshToken }),
      });
      if (res.ok) {
        const data = await res.json();
        _fbIdToken = data.id_token;
        _fbRefreshToken = data.refresh_token;
        _fbTokenExpiry = now + Number(data.expires_in) * 1000;
        writeJson(FIREBASE_TOKEN_FILE, { refreshToken: _fbRefreshToken });
        return _fbIdToken;
      }
    } catch (e) {
      console.warn('Firebase token refresh failed, signing in fresh:', e.message);
    }
  }

  // Anonymous sign-in (creates a new anonymous account)
  const res = await fetch(FIREBASE_AUTH_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ returnSecureToken: true }),
  });
  if (!res.ok) throw new Error(`Firebase anonymous auth failed: HTTP ${res.status}`);
  const data = await res.json();
  _fbIdToken = data.idToken;
  _fbRefreshToken = data.refreshToken;
  _fbTokenExpiry = now + Number(data.expiresIn) * 1000;
  writeJson(FIREBASE_TOKEN_FILE, { refreshToken: _fbRefreshToken });
  return _fbIdToken;
}

// ── Firestore REST helpers ────────────────────────────────────────────────────

// Stable document ID from subscription endpoint
function subDocId(endpoint) {
  return crypto.createHash('sha256').update(endpoint).digest('base64url');
}

// Push subscription → Firestore document fields
function toFirestoreDoc(sub) {
  return {
    fields: {
      endpoint:       { stringValue: sub.endpoint },
      p256dh:         { stringValue: sub.keys?.p256dh || '' },
      auth:           { stringValue: sub.keys?.auth || '' },
      expirationTime: { stringValue: sub.expirationTime ? String(sub.expirationTime) : '' },
      userId:         { stringValue: sub.userId ? String(sub.userId) : '' },
    },
  };
}

// Firestore document fields → push subscription object
function fromFirestoreDoc(doc) {
  const f = doc.fields || {};
  const endpoint = f.endpoint?.stringValue || '';
  const p256dh   = f.p256dh?.stringValue || '';
  const auth     = f.auth?.stringValue || '';
  if (!endpoint || !p256dh || !auth) return null;
  return {
    endpoint,
    keys: { p256dh, auth },
    expirationTime: f.expirationTime?.stringValue || null,
    userId:         f.userId?.stringValue || null,
  };
}

async function firestoreRequest(method, urlPath, body) {
  const token = await getFirebaseToken();
  return fetch(`${FIRESTORE_BASE}${urlPath}`, {
    method,
    headers: {
      Authorization:  `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

// Load all subscriptions from Firestore. Returns array on success, null on error.
async function loadSubscriptionsFromFirestore() {
  try {
    const res = await firestoreRequest('GET', '/pushSubscriptions?pageSize=500');
    if (!res.ok) {
      console.warn('Firestore load failed: HTTP', res.status);
      return null;
    }
    const data = await res.json();
    if (!data.documents) return []; // empty collection
    return data.documents.map(fromFirestoreDoc).filter(Boolean);
  } catch (e) {
    console.warn('Firestore load error:', e.message);
    return null;
  }
}

// Upsert one subscription into Firestore.
async function saveSubscriptionToFirestore(sub) {
  try {
    const docId = subDocId(sub.endpoint);
    const res = await firestoreRequest('PATCH', `/pushSubscriptions/${docId}`, toFirestoreDoc(sub));
    if (!res.ok) console.warn('Firestore save failed: HTTP', res.status);
  } catch (e) {
    console.warn('Firestore save error:', e.message);
  }
}

// Delete one subscription from Firestore by endpoint.
async function removeSubscriptionFromFirestore(endpoint) {
  try {
    const docId = subDocId(endpoint);
    const res = await firestoreRequest('DELETE', `/pushSubscriptions/${docId}`);
    if (!res.ok && res.status !== 404) console.warn('Firestore delete failed: HTTP', res.status);
  } catch (e) {
    console.warn('Firestore delete error:', e.message);
  }
}

// ── Subscription state ────────────────────────────────────────────────────────

// In-memory list is the live source of truth. Firestore and the local file are
// both kept in sync so subscriptions survive Render deploys (Firestore) and
// are available instantly on startup even before Firestore responds (file).
let subscriptions = readJson(SUBSCRIPTIONS_FILE, []);

async function initSubscriptions() {
  const fromFirestore = await loadSubscriptionsFromFirestore();
  if (fromFirestore === null) {
    console.log(`Firestore unavailable — loaded ${subscriptions.length} subscription(s) from local file.`);
    return;
  }
  if (fromFirestore.length === 0 && subscriptions.length > 0) {
    // Firestore is empty (first run after migration) — seed it from the local file.
    console.log(`Seeding Firestore with ${subscriptions.length} subscription(s) from local file…`);
    await Promise.all(subscriptions.map(saveSubscriptionToFirestore));
  } else {
    // Firestore is the authority.
    subscriptions = fromFirestore;
    writeJson(SUBSCRIPTIONS_FILE, subscriptions);
  }
  console.log(`Push subscriptions ready: ${subscriptions.length} subscriber(s).`);
}

// ── Round helpers ─────────────────────────────────────────────────────────────

function currentRoundId(now = new Date()) {
  const round = new Date(now);
  round.setSeconds(0, 0);
  round.setMinutes(round.getMinutes() < 30 ? 0 : 30);
  return round.toISOString();
}

// ── Push delivery ─────────────────────────────────────────────────────────────

function sendPush(payload, excludeEndpoint = null, ttl = 300) {
  const body = JSON.stringify({
    ...payload,
    icon: './pwa-icon-192.png',
    badge: './pwa-icon-192.png',
  });
  // urgency:high → bypass battery-saver queues on Android (FCM) and iOS (APNs)
  // ttl          → how long (seconds) the push service holds the message if the
  //                device is offline. Default 300 s (5 min). Confirmed = 600 s.
  const pushOptions = { urgency: 'high', TTL: ttl };

  const targets = subscriptions.filter((s) => s.endpoint !== excludeEndpoint);
  console.log(`[push] Sending "${payload.title}" to ${targets.length} subscriber(s) (TTL=${ttl}s)`);

  const sends = subscriptions.map(async (subscription) => {
    if (subscription.endpoint === excludeEndpoint) return subscription;
    try {
      await webpush.sendNotification(subscription, body, pushOptions);
      console.log(`[push] ✓ delivered to ${subscription.endpoint.slice(0, 60)}…`);
      return subscription;
    } catch (error) {
      const status = error.statusCode;
      console.warn(`[push] ✗ delivery failed (HTTP ${status || '?'}): ${error.message || ''} → endpoint: ${subscription.endpoint.slice(0, 60)}…`);
      // 404/410 = endpoint gone; 401/403 = bad VAPID key / revoked → drop it
      if (status === 404 || status === 410 || status === 401 || status === 403) {
        removeSubscriptionFromFirestore(subscription.endpoint).catch(() => {});
        return null;
      }
      return subscription;
    }
  });

  return Promise.all(sends).then((remaining) => {
    const kept = remaining.filter(Boolean);
    if (kept.length !== subscriptions.length) {
      console.log(`[push] Dropped ${subscriptions.length - kept.length} expired subscription(s). ${kept.length} remaining.`);
    }
    subscriptions = kept;
    writeJson(SUBSCRIPTIONS_FILE, subscriptions);
  });
}

// ── Weekly gains tracking ─────────────────────────────────────────────────────
// Tracks per-member rep baseline + current rep for Hidden Cloud (clan 777).
// Writes to Firestore weeklyGains/777 at most every WEEKLY_GAINS_SYNC_INTERVAL_MS,
// and only when something actually changed, to minimise Firestore writes.
// On startup, if the local file is missing or from a previous week, the correct
// weekStartRep baselines are restored from Firestore automatically.

let weeklyGainsState = readJson(WEEKLY_GAINS_FILE, { weekKey: null, members: {} });
let _weeklyGainsSyncTimer = null;
let _lastWeeklyGainsSync  = 0;
let weeklyGainsWriteAllowed = false;
let weeklyGainsRestoreRetryTimer = null;

// A Replit server can restart while Firestore is temporarily unavailable. Do
// not let the first live poll turn the current reputation into a new baseline
// and then write that reset back over the real weekly baseline in Firestore.
function scheduleWeeklyGainsRestoreRetry() {
  if (weeklyGainsWriteAllowed || weeklyGainsRestoreRetryTimer) return;
  weeklyGainsRestoreRetryTimer = setTimeout(async () => {
    weeklyGainsRestoreRetryTimer = null;
    await restoreWeeklyGainsFromFirestore();
    if (!weeklyGainsWriteAllowed) {
      scheduleWeeklyGainsRestoreRetry();
    } else if (weeklyGainsState.weekKey && Object.keys(weeklyGainsState.members || {}).length > 0) {
      writeJson(WEEKLY_GAINS_FILE, weeklyGainsState);
      syncWeeklyGainsToFirestore().catch((e) =>
        console.warn('[weekly] Retry sync error:', e.message));
    }
  }, WEEKLY_GAINS_RESTORE_RETRY_MS);
}

// Formats a UTC ms timestamp as a PH-time (UTC+8) YYYY-MM-DD date string.
// Used only for display labels (weekStartLabel/weekEndLabel) — not for any
// rollover logic, since seasons don't align to calendar days.
const PH_OFFSET_MS = 8 * 3_600_000;
function toPhDateStr(utcMs) {
  return new Date(utcMs + PH_OFFSET_MS).toISOString().slice(0, 10);
}

// Weekly gains are cut into real 7-day blocks, anchored to when the current
// season started (not a fixed Monday–Sunday calendar week, since seasons
// don't line up with that and can end mid-day, e.g. ~1PM PH). `json.season`
// is read straight from the same rankings poll: `season.id` tells us when a
// new season has begun, and `season.end_time_ts` (Unix seconds) tells us
// exactly when to stop counting for the one that's ending.
//
// Anchoring: the API never exposes a season's start time, so it's captured
// the moment a new season.id is first observed (accurate to one poll cycle,
// ~5s). Every later weekly boundary for that season is `seasonStartTs + N *
// WEEK_MS`, so cuts land on the same time-of-day the season began and never
// drift. If a season's length isn't an exact multiple of 7 days, the final
// week of that season is simply shorter — it's still cut and archived at
// seasonEndTs like any other week.
function buildWeekEndTs(weekStartTs, seasonEndTs) {
  return Math.min(weekStartTs + WEEK_MS, seasonEndTs);
}

function startNewWeek(seasonId, seasonEndTs, weekStartTs, weekIndex) {
  const weekEndTs = buildWeekEndTs(weekStartTs, seasonEndTs);
  const weekStartLabel = toPhDateStr(weekStartTs);
  return {
    weekKey: weekStartLabel, weekStartLabel, weekEndLabel: toPhDateStr(weekEndTs),
    seasonId, seasonEndTs, seasonStartTs: null, // seasonStartTs filled in by caller
    weekIndex, weekStartTs, weekEndTs,
    members: {},
  };
}

function updateWeeklyGains(json) {
  const hcClan = (json.clans || []).find((c) => c.id === HIDDEN_CLOUD_CLAN_ID);
  if (!hcClan) return;
  const season = json.season;
  if (!season || !season.id || !season.end_time_ts) return; // no season data this poll — try again next poll

  const now         = Date.now();
  const seasonId     = season.id;
  const seasonEndTs  = Number(season.end_time_ts) * 1000; // seconds → ms

  if (weeklyGainsState.seasonId && weeklyGainsState.seasonId !== seasonId) {
    // Season rollover — archive whatever week was in progress (possibly a
    // short final week if the season ended mid-week), then start the new
    // season. seedSeasonState uses the known 1PM PH anchor if this is that
    // transition, otherwise "now".
    archiveWeekToFirestore(weeklyGainsState).catch((e) =>
      console.warn('[weekly] Archive error:', e.message));
    weeklyGainsState = seedSeasonState(seasonId, seasonEndTs, now);
  } else if (!weeklyGainsState.seasonId) {
    // First time we've seen season data for this run.
    // (A mid-season server restart is handled by restoreWeeklyGainsFromFirestore
    // before this ever runs, so this path only fires on a true fresh start.)
    const hasMigratedAnchor = typeof weeklyGainsState.weekStartTs === 'number';
    if (!hasMigratedAnchor) {
      // Fresh install, or migrating from the pre-weekly-cuts state shape.
      weeklyGainsState = seedSeasonState(seasonId, seasonEndTs, now);
    } else {
      weeklyGainsState.seasonId    = seasonId;
      weeklyGainsState.seasonEndTs = seasonEndTs;
      if (!weeklyGainsState.members) weeklyGainsState.members = {};
    }
  } else if (weeklyGainsState.seasonEndTs !== seasonEndTs) {
    // Same season, but its end time shifted (rare) — keep labels in sync.
    weeklyGainsState.seasonEndTs  = seasonEndTs;
    weeklyGainsState.weekEndTs    = buildWeekEndTs(weeklyGainsState.weekStartTs, seasonEndTs);
    weeklyGainsState.weekEndLabel = toPhDateStr(weeklyGainsState.weekEndTs);
  }

  // Safety net: the week anchor fields can end up missing or nonsensical —
  // e.g. adopted from an older-schema Firestore doc that predates this
  // week-cutting logic, where the new fields come back as null. Trusting
  // that blindly would make the loop below treat null as epoch (1970) and
  // walk forward one week at a time thousands of times to catch up to now,
  // firing that many Firestore writes and re-baselining members thousands
  // of times in a row. Detect that up front and reseed directly instead.
  const MIN_VALID_TS = Date.UTC(2024, 0, 1); // sanity floor — this app didn't exist before this
  const hasValidWeekAnchor =
    typeof weeklyGainsState.seasonStartTs === 'number' && weeklyGainsState.seasonStartTs > MIN_VALID_TS &&
    typeof weeklyGainsState.weekStartTs   === 'number' && weeklyGainsState.weekStartTs >= weeklyGainsState.seasonStartTs &&
    typeof weeklyGainsState.weekEndTs     === 'number' && weeklyGainsState.weekEndTs > weeklyGainsState.weekStartTs &&
    weeklyGainsState.weekEndTs <= weeklyGainsState.seasonEndTs + 1000 &&
    Number.isInteger(weeklyGainsState.weekIndex) && weeklyGainsState.weekIndex > 0 && weeklyGainsState.weekIndex < 1000;

  if (!hasValidWeekAnchor) {
    console.warn('[weekly] Invalid/missing week anchor detected — reseeding from current reputation instead of walking forward from it.');
    const prevMembers = weeklyGainsState.members || {};
    const reseeded = seedSeasonState(weeklyGainsState.seasonId, weeklyGainsState.seasonEndTs, now);
    // Carry forward any gain already legitimately observed this (broken)
    // week rather than zeroing it out, so real tracked progress isn't lost.
    for (const [id, m] of Object.entries(prevMembers)) {
      if (typeof m.currentRep !== 'number') continue;
      const priorGain = Math.max(0, m.currentRep - (typeof m.weekStartRep === 'number' ? m.weekStartRep : m.currentRep));
      reseeded.members[id] = { name: m.name, weekStartRep: m.currentRep - priorGain, currentRep: m.currentRep };
    }
    weeklyGainsState = reseeded;
    writeJson(WEEKLY_GAINS_FILE, weeklyGainsState);
    if (weeklyGainsWriteAllowed) {
      syncWeeklyGainsToFirestore().catch((e) =>
        console.warn('[weekly] Reseed sync error:', e.message));
    }
  }

  // Weekly cut: once the current week's boundary has passed (and the season
  // itself hasn't ended yet), archive it and start the next 7-day block. A
  // loop (not a single if) so a long server outage catches up to the real
  // current week in one poll instead of needing one poll cycle per missed
  // week. Capped as defense-in-depth — the safety net above should mean this
  // never runs more than a couple of times in practice.
  let cutIterations = 0;
  while (now >= weeklyGainsState.weekEndTs && now < weeklyGainsState.seasonEndTs) {
    if (++cutIterations > 10) {
      console.error('[weekly] Weekly-cut loop exceeded 10 iterations — reseeding instead of continuing to walk forward.');
      weeklyGainsState = seedSeasonState(weeklyGainsState.seasonId, weeklyGainsState.seasonEndTs, now);
      break;
    }
    archiveWeekToFirestore(weeklyGainsState).catch((e) =>
      console.warn('[weekly] Archive error:', e.message));
    const prevMembers = weeklyGainsState.members;
    const next = startNewWeek(
      weeklyGainsState.seasonId,
      weeklyGainsState.seasonEndTs,
      weeklyGainsState.weekEndTs, // next week starts exactly where the last one ended
      weeklyGainsState.weekIndex + 1,
    );
    next.seasonStartTs = weeklyGainsState.seasonStartTs;
    // Re-baseline every currently-known member to their rep right now, so
    // the new week starts counting from zero.
    for (const [id, m] of Object.entries(prevMembers)) {
      next.members[id] = { name: m.name, weekStartRep: m.currentRep, currentRep: m.currentRep };
    }
    weeklyGainsState = next;
  }

  // Once the season has actually ended, freeze gains — the rankings API can
  // keep reporting the same season.id for a little while after end_time_ts
  // passes, and reputation itself may keep moving; without this, gains kept
  // accruing past the season's real end (the bug being fixed here).
  const seasonEnded = now >= weeklyGainsState.seasonEndTs;

  const members = weeklyGainsState.members;
  let changed = false;
  let newBaselineAdded = false; // a brand-new mid-season join was just baselined

  // Build the set of member IDs currently in the clan.
  const currentMemberIds = new Set((hcClan.member_list || []).map((m) => String(m.id)));

  for (const member of hcClan.member_list || []) {
    const id  = String(member.id);
    const rep = member.reputation;
    if (!members[id]) {
      // Still baseline a newly-seen member even after the season ended, so
      // they show up correctly once the next season starts — they just
      // won't have accrued anything for this (already over) season.
      members[id] = { name: member.name, weekStartRep: rep, currentRep: rep };
      changed = true;
      newBaselineAdded = true;
    } else {
      if (members[id].name !== member.name)  { members[id].name = member.name; changed = true; }
      // Reputation is cumulative for the season. Ignore a stale or
      // out-of-order rankings response so a previously recorded gain cannot
      // temporarily fall back to zero — and stop advancing entirely once
      // the season has ended.
      if (!seasonEnded && typeof rep === 'number' && rep > members[id].currentRep) {
        members[id].currentRep = rep;
        changed = true;
      }
    }
  }

  // Remove members who have left the clan so they no longer appear in weekly gains.
  for (const id of Object.keys(members)) {
    if (!currentMemberIds.has(id)) {
      console.log(`[weekly] Removing ex-member ${members[id]?.name || id} from weekly gains state.`);
      delete members[id];
      changed = true;
    }
  }

  if (changed) {
    // Keep an unverified in-memory state while Firestore restore is pending,
    // but never persist it until we know it is safe to do so.
    if (weeklyGainsWriteAllowed) {
      writeJson(WEEKLY_GAINS_FILE, weeklyGainsState);
      if (newBaselineAdded) {
        // A mid-season join's baseline only exists in memory until it reaches
        // Firestore. Push it immediately instead of waiting up to 5 minutes,
        // so a crash/restart in that window can't erase it like before.
        syncWeeklyGainsToFirestore().catch((e) =>
          console.warn('[weekly] Immediate new-member baseline sync error:', e.message));
      } else {
        scheduleWeeklyGainsSync(); // throttled Firestore sync (at most every 5 min)
      }
    }
  }
}


// Writes current weeklyGainsState to Firestore weeklyGains/777, throttled to at
// most once every WEEKLY_GAINS_SYNC_INTERVAL_MS. Called whenever rep values change.
function scheduleWeeklyGainsSync() {
  if (!weeklyGainsWriteAllowed) return;
  if (_weeklyGainsSyncTimer) return; // already queued
  const delay = Math.max(0, WEEKLY_GAINS_SYNC_INTERVAL_MS - (Date.now() - _lastWeeklyGainsSync));
  _weeklyGainsSyncTimer = setTimeout(() => {
    _weeklyGainsSyncTimer = null;
    syncWeeklyGainsToFirestore().catch((e) => console.warn('[weekly] Sync error:', e.message));
  }, delay);
}

async function syncWeeklyGainsToFirestore() {
  if (!weeklyGainsWriteAllowed) return;
  if (!weeklyGainsState.weekKey) return;
  _lastWeeklyGainsSync = Date.now();
  const members = {};
  for (const [id, m] of Object.entries(weeklyGainsState.members)) {
    members[id] = {
      name:         m.name,
      weekStartRep: m.weekStartRep,
      currentRep:   m.currentRep,
      weekGain:     Math.max(0, m.currentRep - m.weekStartRep),
      lastUpdated:  Date.now(),
    };
  }
  const res = await firestoreRequest('PATCH', '/weeklyGains/777', fsDoc({
    weekKey:        weeklyGainsState.weekKey,
    weekStartLabel: weeklyGainsState.weekStartLabel,
    weekEndLabel:   weeklyGainsState.weekEndLabel,
    weekIndex:      weeklyGainsState.weekIndex,
    weekStartTs:    weeklyGainsState.weekStartTs,
    weekEndTs:      weeklyGainsState.weekEndTs,
    seasonId:       weeklyGainsState.seasonId,
    seasonStartTs:  weeklyGainsState.seasonStartTs,
    seasonEndTs:    weeklyGainsState.seasonEndTs,
    clanId:         777,
    lastUpdated:    Date.now(),
    members,
  }));
  if (res.ok) console.log('[weekly] Synced weeklyGains/777 to Firestore.');
  else        console.warn('[weekly] Firestore sync failed:', res.status);
}

// On startup: always read Firestore weeklyGains/777 and reconcile with local state.
//
// Unlike a calendar week, "current season" can't be computed independently
// of the rankings API, so this step can't pre-verify whether the cached data
// is stale the way the old Monday-Sunday version could. Instead:
//   A) Local file has no season yet → take Firestore's copy as a best-effort
//      starting point; the first live poll's rollover check (in
//      updateWeeklyGains) will correct it if it turns out to be a finished season/week.
//   B) Local file's seasonId AND weekStartTs both match Firestore's → MERGE:
//      use the lower weekStartRep per member. This corrects baselines that
//      were wrongly set to "current rep" (e.g. after a server restart mid-week
//      lost the real baseline).
//   C) Local file's seasonId differs, or the seasonId matches but weekStartTs
//      doesn't (a weekly cut happened on one instance but not the other) →
//      whichever side has the later weekStartTs is the more advanced state;
//      keep that one as-is rather than merging mismatched weeks' members.
//
// After reconciliation, the corrected state is immediately written back to Firestore
// so any other running instance can benefit from the most accurate baselines.
async function restoreWeeklyGainsFromFirestore() {
  console.log('[weekly] Syncing baselines with Firestore…');
  try {
    const res = await firestoreRequest('GET', '/weeklyGains/777');
    if (!res.ok) {
      console.warn('[weekly] Firestore read failed:', res.status,
        weeklyGainsState.seasonId ? '— keeping local state.' : '— starting fresh.');
      if (res.status === 404) {
        // No document exists yet: this is a first-ever initialization, not a
        // transient outage. The next live poll may safely establish the
        // current season's baseline.
        weeklyGainsWriteAllowed = true;
        return;
      }
      // Even a populated local file may be behind a healthier Firestore copy.
      // It is safe to keep serving it, but not to write it back until the
      // remote baseline has been verified.
      weeklyGainsWriteAllowed = false;
      scheduleWeeklyGainsRestoreRetry();
      return;
    }
    const doc = await res.json();

    const fsVal = (v) => {
      if (!v) return null;
      if (v.stringValue  !== undefined) return v.stringValue;
      if (v.integerValue !== undefined) return Number(v.integerValue);
      if (v.doubleValue  !== undefined) return Number(v.doubleValue);
      if (v.booleanValue !== undefined) return v.booleanValue;
      if (v.mapValue)   { const o = {}; for (const [k, vv] of Object.entries(v.mapValue.fields || {})) o[k] = fsVal(vv); return o; }
      if (v.arrayValue) return (v.arrayValue.values || []).map(fsVal);
      return null;
    };

    if (!doc.fields) {
      console.log('[weekly] weeklyGains/777 is empty in Firestore.');
      // An explicitly empty document is safe for first-time initialization.
      weeklyGainsWriteAllowed = true;
      return;
    }

    const fsSeasonId   = fsVal(doc.fields.seasonId);
    const fsWeekStartTs = fsVal(doc.fields.weekStartTs);

    const sameWeek = weeklyGainsState.seasonId === fsSeasonId &&
      weeklyGainsState.weekStartTs === fsWeekStartTs;

    if (weeklyGainsState.seasonId && !sameWeek) {
      // Case C — different season, or same season but a different weekly
      // block. Keep whichever side is further along (later weekStartTs);
      // don't merge members across mismatched weeks.
      const localIsNewer = !fsWeekStartTs ||
        (typeof weeklyGainsState.weekStartTs === 'number' && weeklyGainsState.weekStartTs >= fsWeekStartTs);
      if (localIsNewer) {
        console.log('[weekly] Firestore doc is from an earlier week/season — local state kept as-is.');
        weeklyGainsWriteAllowed = true;
        return;
      }
      console.log('[weekly] Firestore doc is from a later week/season — adopting it.');
      // Fall through to Case A's adoption logic below using the Firestore copy.
    } else if (weeklyGainsState.seasonId && sameWeek) {
      // Case B — same season, same weekly block: merge, keeping the safer
      // (lower) weekStartRep.
      const rawMembers = fsVal(doc.fields.members) || {};
      let corrected = 0;
      for (const [id, fsm] of Object.entries(rawMembers)) {
        const local = weeklyGainsState.members[id];
        if (!local) {
          weeklyGainsState.members[id] = { name: fsm.name, weekStartRep: fsm.weekStartRep, currentRep: fsm.currentRep };
          corrected++;
        } else {
          // The baseline is immutable for the week. If two server instances
          // disagree, the lower value is the only safe choice because it
          // preserves all gains already observed.
          if (typeof fsm.weekStartRep === 'number' && fsm.weekStartRep < local.weekStartRep) {
            weeklyGainsState.members[id].weekStartRep = fsm.weekStartRep;
            corrected++;
          }
          // Keep the freshest observed reputation when restoring. This also
          // prevents a restarted instance from briefly moving the live value
          // backwards while it catches up with the rankings poller.
          if (typeof fsm.currentRep === 'number' &&
              fsm.currentRep > weeklyGainsState.members[id].currentRep) {
            weeklyGainsState.members[id].currentRep = fsm.currentRep;
            corrected++;
          }
        }
      }
      if (corrected > 0) {
        writeJson(WEEKLY_GAINS_FILE, weeklyGainsState);
        console.log(`[weekly] Corrected ${corrected} member baseline(s) from Firestore (lower weekStartRep used).`);
      } else {
        console.log('[weekly] Local baselines are already optimal — no correction needed.');
      }
      weeklyGainsWriteAllowed = true;
      return;
    }

    // Case A — no local season yet: take Firestore's copy as a starting point.
    const rawMembers = fsVal(doc.fields.members) || {};
    const members = {};
    for (const [id, m] of Object.entries(rawMembers)) {
      members[id] = { name: m.name, weekStartRep: m.weekStartRep, currentRep: m.currentRep };
    }
    weeklyGainsState = {
      weekKey:        fsVal(doc.fields.weekKey),
      weekStartLabel: fsVal(doc.fields.weekStartLabel),
      weekEndLabel:   fsVal(doc.fields.weekEndLabel),
      weekIndex:      fsVal(doc.fields.weekIndex),
      weekStartTs:    fsVal(doc.fields.weekStartTs),
      weekEndTs:      fsVal(doc.fields.weekEndTs),
      seasonId:       fsSeasonId,
      seasonStartTs:  fsVal(doc.fields.seasonStartTs),
      seasonEndTs:    fsVal(doc.fields.seasonEndTs),
      members,
    };
    writeJson(WEEKLY_GAINS_FILE, weeklyGainsState);
    console.log(`[weekly] Restored ${Object.keys(members).length} member baselines from Firestore (season ${fsSeasonId}, week ${weeklyGainsState.weekIndex}).`);
    weeklyGainsWriteAllowed = true;
  } catch (e) {
    console.warn('[weekly] Restore error:', e.message);
    weeklyGainsWriteAllowed = false;
    scheduleWeeklyGainsRestoreRetry();
  }
}

async function archiveWeekToFirestore(st) {
  const membersArr = Object.values(st.members)
    .map((m) => ({
      name:     m.name,
      weekGain: Math.max(0, m.currentRep - m.weekStartRep),
      startRep: m.weekStartRep,
      endRep:   m.currentRep,
    }))
    .sort((a, b) => b.weekGain - a.weekGain);
  const res = await firestoreRequest('PATCH', `/weeklyGainsHistory/${st.weekKey}`, fsDoc({
    weekKey:        st.weekKey,
    weekStartLabel: st.weekStartLabel,
    weekEndLabel:   st.weekEndLabel,
    weekIndex:      st.weekIndex,
    weekStartTs:    st.weekStartTs,
    weekEndTs:      st.weekEndTs,
    seasonId:       st.seasonId,
    seasonStartTs:  st.seasonStartTs,
    members:        membersArr,
  }));
  if (!res.ok) console.warn('[weekly] Archive PATCH failed:', res.status);
  else         console.log('[weekly] Archived week', st.weekKey, 'to weeklyGainsHistory.');
}

// ── Discord webhook URL cache ─────────────────────────────────────────────────
// Persisted to disk so it survives server restarts without a Firestore read.
// TTL is 1 hour — if admin updates the URL, restart the server to force refresh.
const _savedWebhook = readJson(DISCORD_WEBHOOK_CACHE_FILE, { url: null, fetchedAt: 0 });
let discordWebhookCache = (_savedWebhook.url !== null &&
  Date.now() - (_savedWebhook.fetchedAt || 0) < DISCORD_WEBHOOK_CACHE_TTL_MS)
  ? _savedWebhook : { url: null, fetchedAt: 0 };

async function getDiscordWebhookUrl() {
  const now = Date.now();
  if (discordWebhookCache.url !== null && now - discordWebhookCache.fetchedAt < DISCORD_WEBHOOK_CACHE_TTL_MS) {
    return discordWebhookCache.url;
  }
  try {
    const snap = await firestoreRequest('GET', '/config/discordWebhook');
    if (snap.ok) {
      const doc = await snap.json();
      discordWebhookCache = { url: doc.fields?.url?.stringValue || '', fetchedAt: now };
      writeJson(DISCORD_WEBHOOK_CACHE_FILE, discordWebhookCache); // persist across restarts
      return discordWebhookCache.url;
    }
  } catch (e) {
    console.warn('Discord: failed to read webhook URL from Firestore:', e.message);
  }
  return discordWebhookCache.url || '';
}

// ── Bleeding detector (server-side, runs even when no client is open) ─────────

let detectorState = readJson(DETECTOR_STATE_FILE, {
  roundId: null,
  previous: null,
  memberGainEvents: {},
  possibleBleedSince: null,
  possibleNotifiedRoundId: null,
});

function recordGainEvents(json) {
  const now = Date.now();
  const previous = detectorState.previous;
  const events = detectorState.memberGainEvents || {};
  const current = new Map(json.clans.map((clan) => [clan.id, clan]));

  for (const clan of json.clans) {
    const previousClan = previous?.clans?.find((item) => item.id === clan.id);
    for (const member of clan.member_list || []) {
      const key = `${clan.id}_${member.id}`;
      const previousMember = previousClan?.member_list?.find((item) => item.id === member.id);
      if (previousMember && member.reputation > previousMember.reputation) {
        events[key] = [...(events[key] || []), now].filter((ts) => now - ts <= 15000);
      } else {
        events[key] = (events[key] || []).filter((ts) => now - ts <= 15000);
      }
    }
  }

  const bleedingClanIds = new Set();
  for (const clan of json.clans) {
    for (const member of clan.member_list || []) {
      const timestamps = events[`${clan.id}_${member.id}`] || [];
      for (let i = 1; i < timestamps.length; i++) {
        if (timestamps[i] - timestamps[i - 1] <= 10000) {
          bleedingClanIds.add(clan.id);
          break;
        }
      }
      if (bleedingClanIds.has(clan.id)) break;
    }
  }

  detectorState.previous = json;
  detectorState.memberGainEvents = events;
  return [...bleedingClanIds].map((id) => current.get(id)).filter(Boolean);
}

// ── Events: reputation-gain tracking + Ping Event ping tallying ───────────────
// Powers the "Live Progress" leaderboard already built into the client (the
// `eventGains/{eventId}` doc it listens to) for every event, and additionally
// tracks per-member bleed-ping counts for events with `trackPings: true`
// ("Ping Events") so the leaderboard can rank leading pingers and flag who has
// met the event's minimum reputation-gain eligibility bar.

const EVENT_GAINS_FILE            = path.join(DATA_DIR, 'event-gains-state.json');
const EVENT_GAINS_SYNC_INTERVAL_MS = 20_000;      // throttle eventGains/{id} Firestore writes
const EVENT_PING_TALLY_INTERVAL_MS = 20_000;      // how often to re-tally bleedEventLog for Ping Events
const EVENTS_LIST_REFRESH_MS       = 30_000;      // how often to re-read the events collection
const EVENT_GAINS_GRACE_MS         = 10 * 60_000; // keep tracking 10 min after an event ends

let cachedEvents           = [];   // events worth tracking right now (started, not long-ended)
let lastEventsListFetch    = 0;
let eventGainsState        = readJson(EVENT_GAINS_FILE, {}); // eventId → { members: { id → {name,startRep,currentRep,pings} } }
let lastEventPingTally     = {};   // eventId → ms of last bleedEventLog tally
const _eventGainsSyncTimers = {};  // eventId → timeout handle
const _lastEventGainsSync   = {};  // eventId → ms

// Structured-query REST call (list/GET only supports pagination, not filters —
// this is needed to filter bleedEventLog by action + a ts range).
async function firestoreRunQuery(structuredQuery) {
  const token = await getFirebaseToken();
  const res = await fetch(`${FIRESTORE_BASE}:runQuery`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ structuredQuery }),
  });
  if (!res.ok) {
    const bodyText = await res.text().catch(() => '');
    // On the very first run this typically fails until a Firestore composite
    // index (bleedEventLog: action ASC, ts ASC) exists — the error body from
    // Firestore includes a direct console link to auto-create it.
    throw new Error(`Firestore runQuery HTTP ${res.status}: ${bodyText.slice(0, 500)}`);
  }
  const rows = await res.json();
  return rows
    .filter((r) => r.document)
    .map((r) => {
      const out = { id: r.document.name.split('/').pop() };
      for (const [k, v] of Object.entries(r.document.fields || {})) out[k] = fsRestVal(v);
      return out;
    });
}

// Refreshes `cachedEvents` from Firestore `events`, throttled. Keeps any event
// that has started (or hasn't ended long ago) so its gains stay up to date.
async function refreshCachedEvents() {
  const now = Date.now();
  if (now - lastEventsListFetch < EVENTS_LIST_REFRESH_MS) return;
  lastEventsListFetch = now;
  try {
    const docs = [];
    let pageToken = null;
    do {
      const qs = 'pageSize=200' + (pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : '');
      const res = await firestoreRequest('GET', `/events?${qs}`);
      if (!res.ok) return; // leave cachedEvents untouched on any read failure
      const data = await res.json();
      for (const d of data.documents || []) {
        const out = { id: d.name.split('/').pop() };
        for (const [k, v] of Object.entries(d.fields || {})) out[k] = fsRestVal(v);
        docs.push(out);
      }
      pageToken = data.nextPageToken || null;
    } while (pageToken);

    cachedEvents = docs.filter((ev) =>
      typeof ev.startTs === 'number' &&
      typeof ev.endTs === 'number' &&
      now <= ev.endTs + EVENT_GAINS_GRACE_MS
    );
  } catch (e) {
    console.warn('[events] Failed to refresh events list:', e.message);
  }
}

function scheduleEventGainsSync(eventId) {
  if (_eventGainsSyncTimers[eventId]) return; // already queued
  const last  = _lastEventGainsSync[eventId] || 0;
  const delay = Math.max(0, EVENT_GAINS_SYNC_INTERVAL_MS - (Date.now() - last));
  _eventGainsSyncTimers[eventId] = setTimeout(() => {
    _eventGainsSyncTimers[eventId] = null;
    syncEventGainsToFirestore(eventId).catch((e) =>
      console.warn(`[events] Sync error for ${eventId}:`, e.message));
  }, delay);
}

async function syncEventGainsToFirestore(eventId) {
  const st = eventGainsState[eventId];
  if (!st) return;
  _lastEventGainsSync[eventId] = Date.now();
  const members = {};
  for (const [id, m] of Object.entries(st.members)) {
    members[id] = {
      name:         m.name,
      startRep:     m.startRep,
      currentRep:   m.currentRep,
      eventGain:    Math.max(0, m.currentRep - m.startRep),
      pings:        m.pings || 0,
      pendingPings: m.pendingPings || 0,
    };
  }
  const res = await firestoreRequest('PATCH', `/eventGains/${eventId}`, fsDoc({
    lastUpdated: Date.now(),
    members,
  }));
  if (!res.ok) console.warn(`[events] eventGains sync failed for ${eventId}:`, res.status);
}

// Rounds are aligned to the game's fixed :00/:30 half-hour marks — mirrors
// getRoundStart() in index.html so a ping's "round" matches what the client
// shows (and matches when the client's Unmark button stops being clickable).
const ROUND_LENGTH_MS = 30 * 60_000;
function roundStartMs(ts) {
  const d = new Date(ts);
  d.setSeconds(0, 0);
  if (d.getMinutes() < 30) d.setMinutes(0); else d.setMinutes(30);
  return d.getTime();
}

// Tallies bleed pings ('marked' bleedEventLog entries with a byId) that fall
// within [event.startTs, min(now, event.endTs)] for Ping Events. Throttled
// per-event since it's an extra Firestore query.
//
// A ping only becomes a *confirmed* point once the 30-min round it was made
// in has fully ended — that's also the exact window during which it can
// still be unmarked in-app (see markedInCurrentRound in toggleClanBleed), so
// any ping that gets unmarked before its round closes is dropped instead of
// counted, whether or not "false alarm" was checked — the checkbox only
// labels *why* for the History tab. Entries flagged `falseAlarm: true` or
// `unmarked: true` (see confirmUnmarkBleed in index.html) never count,
// confirmed or pending.
async function tallyEventPings(ev) {
  const now  = Date.now();
  const last = lastEventPingTally[ev.id] || 0;
  if (now - last < EVENT_PING_TALLY_INTERVAL_MS) return;
  lastEventPingTally[ev.id] = now;

  const startIso = new Date(ev.startTs).toISOString();
  const endIso   = new Date(Math.min(now, ev.endTs)).toISOString();

  let rows;
  try {
    rows = await firestoreRunQuery({
      from: [{ collectionId: 'bleedEventLog' }],
      where: {
        compositeFilter: {
          op: 'AND',
          filters: [
            { fieldFilter: { field: { fieldPath: 'action' }, op: 'EQUAL', value: { stringValue: 'marked' } } },
            { fieldFilter: { field: { fieldPath: 'ts' }, op: 'GREATER_THAN_OR_EQUAL', value: { stringValue: startIso } } },
            { fieldFilter: { field: { fieldPath: 'ts' }, op: 'LESS_THAN_OR_EQUAL', value: { stringValue: endIso } } },
          ],
        },
      },
      limit: 1000,
    });
  } catch (e) {
    console.warn(`[events] ping tally query failed for ${ev.id}:`, e.message);
    return;
  }

  const confirmedCounts = {};
  const pendingCounts   = {};
  for (const row of rows) {
    if (!row.byId) continue;                 // log entries written before the Ping Event feature have no linked member id
    if (row.falseAlarm || row.unmarked) continue; // cleared before its round closed — never counts, pending or confirmed

    const roundEnd = roundStartMs(row.ts) + ROUND_LENGTH_MS;
    if (now >= roundEnd) {
      confirmedCounts[row.byId] = (confirmedCounts[row.byId] || 0) + 1;
    } else {
      pendingCounts[row.byId] = (pendingCounts[row.byId] || 0) + 1;
    }
  }

  const st = eventGainsState[ev.id];
  if (!st) return;
  let changed = false;
  const allIds = new Set([...Object.keys(confirmedCounts), ...Object.keys(pendingCounts), ...Object.keys(st.members)]);
  for (const id of allIds) {
    if (!st.members[id]) st.members[id] = { name: null, startRep: 0, currentRep: 0, pings: 0, pendingPings: 0 };
    const confirmed = confirmedCounts[id] || 0;
    const pending   = pendingCounts[id] || 0;
    if (st.members[id].pings !== confirmed) { st.members[id].pings = confirmed; changed = true; }
    if (st.members[id].pendingPings !== pending) { st.members[id].pendingPings = pending; changed = true; }
  }
  if (changed) scheduleEventGainsSync(ev.id);
}

// Called every rankings poll (alongside updateWeeklyGains). Snapshots each
// member's reputation baseline the moment an event starts, tracks live gains
// while it's running, and (for Ping Events) tallies pinger standings.
function updateEventGains(json) {
  const hcClan = (json.clans || []).find((c) => c.id === HIDDEN_CLOUD_CLAN_ID);
  if (!hcClan) return;
  const now = Date.now();

  for (const ev of cachedEvents) {
    if (now < ev.startTs) continue; // not started yet — no baseline to snapshot
    if (!eventGainsState[ev.id]) eventGainsState[ev.id] = { members: {} };
    const st = eventGainsState[ev.id];
    let changed = false;

    if (now <= ev.endTs) {
      for (const member of hcClan.member_list || []) {
        const id  = String(member.id);
        const rep = member.reputation;
        if (!st.members[id]) {
          // First time seen during this event — baseline them now (covers
          // both the event's start and anyone who joins the clan mid-event).
          //
          // Ping Events measure reputation gained since the SEASON started,
          // not since the event started — and the rankings API already
          // reports `reputation` as cumulative for the season (see the note
          // in updateWeeklyGains above), so that baseline is always 0; the
          // member's live reputation figure *is* their season-to-date gain.
          // Regular (non-ping) events keep the event-start snapshot, since
          // their conditions are meant to measure gain during the event.
          st.members[id] = { name: member.name, startRep: ev.trackPings ? 0 : rep, currentRep: rep, pings: 0, pendingPings: 0 };
          changed = true;
        } else {
          if (st.members[id].name !== member.name) { st.members[id].name = member.name; changed = true; }
          if (typeof rep === 'number' && rep > st.members[id].currentRep) { st.members[id].currentRep = rep; changed = true; }
        }
      }
    }

    // One-time flag so the client knows the server has started tracking this
    // event (it resets this to false whenever the start time is edited).
    if (!ev.snapshotTaken) {
      ev.snapshotTaken = true;
      firestoreRequest('PATCH', `/events/${ev.id}?updateMask.fieldPaths=snapshotTaken`, fsDoc({ snapshotTaken: true }))
        .catch((e) => console.warn(`[events] snapshotTaken flag write failed for ${ev.id}:`, e.message));
    }

    if (ev.trackPings) tallyEventPings(ev).catch((e) => console.warn(`[events] ping tally error for ${ev.id}:`, e.message));

    if (changed) scheduleEventGainsSync(ev.id);
  }

  if (Object.keys(eventGainsState).length) writeJson(EVENT_GAINS_FILE, eventGainsState);

  // Drop local state for events that have fallen out of the tracking window.
  const liveIds = new Set(cachedEvents.map((e) => e.id));
  for (const id of Object.keys(eventGainsState)) {
    if (!liveIds.has(id)) delete eventGainsState[id];
  }
}

// ── Membership purge ──────────────────────────────────────────────────────────
// Runs every 5 minutes during the poll loop. Removes push subscriptions whose
// userId is no longer in the Hidden Cloud Village member list. Subscriptions
// with no userId (legacy / anonymous) are left untouched.
let lastMembershipPurge = 0;

async function purgeExMemberSubscriptions(json) {
  const hcClan = (json.clans || []).find((c) => c.id === HIDDEN_CLOUD_CLAN_ID);
  if (!hcClan) return; // can't verify — skip this cycle
  const memberIds = new Set((hcClan.member_list || []).map((m) => String(m.id)));

  const before = subscriptions.length;
  const removed = [];
  subscriptions = subscriptions.filter((sub) => {
    if (!sub.userId) return true; // no userId → keep (legacy subscription)
    if (memberIds.has(String(sub.userId))) return true; // still a member → keep
    removed.push(sub);
    return false;
  });

  if (removed.length > 0) {
    console.log(`[membership] Removed ${removed.length} subscription(s) for ex-member(s): ${removed.map((s) => s.userId).join(', ')}`);
    writeJson(SUBSCRIPTIONS_FILE, subscriptions);
    for (const sub of removed) {
      removeSubscriptionFromFirestore(sub.endpoint).catch(() => {});
    }
  } else {
    console.log(`[membership] Purge check complete — all ${before} subscription(s) are current members.`);
  }
  lastMembershipPurge = Date.now();
}

async function pollForPossibleBleeding() {
  try {
    const response = await fetch(API_URL, { cache: 'no-store' });
    if (!response.ok) throw new Error(`rankings HTTP ${response.status}`);
    const json = await response.json();

    // Periodic membership purge — runs every 5 minutes
    if (Date.now() - lastMembershipPurge >= MEMBERSHIP_PURGE_INTERVAL_MS) {
      purgeExMemberSubscriptions(json).catch((e) => console.warn('[membership] Purge error:', e.message));
    }

    const roundId = currentRoundId();
    if (detectorState.roundId !== roundId) {
      detectorState.roundId = roundId;
      detectorState.previous = null;
      detectorState.memberGainEvents = {};
      detectorState.possibleBleedSince = null;
      detectorState.possibleNotifiedRoundId = null;
    }

    updateWeeklyGains(json);

    await refreshCachedEvents();
    updateEventGains(json);

    const bleedingClans = recordGainEvents(json);
    if (bleedingClans.length > POSSIBLE_BLEEDING_CLAN_THRESHOLD) {
      if (!detectorState.possibleBleedSince) detectorState.possibleBleedSince = Date.now();
      if (
        Date.now() - detectorState.possibleBleedSince >= POSSIBLE_BLEEDING_DELAY_MS &&
        detectorState.possibleNotifiedRoundId !== roundId
      ) {
        detectorState.possibleNotifiedRoundId = roundId;
        await sendPush({
          title: '⚠ Possible Bleeding',
          body: `There have been ${bleedingClans.length} clans in Gaining (Bleed) status. Bleeding occurred, hurry and find who is bleeding!`,
          tag: `hidden-cloud-possible-bleeding-${roundId}`,
        });
      }
    } else {
      detectorState.possibleBleedSince = null;
    }
    writeJson(DETECTOR_STATE_FILE, detectorState);
  } catch (error) {
    console.warn('Background bleeding detector error:', error.message);
  }
}

// ── Confirmed bleeds: server-managed state, broadcast via SSE ────────────────
// Replaces per-client Firestore onSnapshot listeners.
// All N connected clients share ONE server-side Firestore read (30 s fallback),
// and receive real-time updates via SSE whenever any user marks/clears a bleed.

const sseClients = new Set();
let serverConfirmedBleeds = {}; // clanId (number) → bleed doc

function broadcastBleeds() {
  const payload = `data: ${JSON.stringify(serverConfirmedBleeds)}\n\n`;
  for (const res of sseClients) {
    try { res.write(payload); } catch { sseClients.delete(res); }
  }
}

// Parses a single Firestore REST typed value to a plain JS value.
function fsRestVal(v) {
  if (!v) return null;
  if (v.stringValue  !== undefined) return v.stringValue;
  if (v.integerValue !== undefined) return Number(v.integerValue);
  if (v.doubleValue  !== undefined) return Number(v.doubleValue);
  if (v.booleanValue !== undefined) return v.booleanValue;
  if (v.timestampValue !== undefined) return new Date(v.timestampValue).getTime();
  if (v.mapValue)   { const o = {}; for (const [k, vv] of Object.entries(v.mapValue.fields || {})) o[k] = fsRestVal(vv); return o; }
  if (v.arrayValue) return (v.arrayValue.values || []).map(fsRestVal);
  return null;
}

// Fallback: reads confirmedBleeds from Firestore once every 30 s, ensuring
// any client that connects after a state change sees the latest data.
//
// IMPORTANT: this must never *blindly replace* serverConfirmedBleeds. A single
// incomplete/partial read (pagination truncation, a security-rule-restricted
// row, a transient Firestore hiccup) would otherwise wipe an active bleed mark
// for every connected client even though nobody unmarked it and the round
// hasn't ended. So we only ever ADD/UPDATE from what we positively read, and
// we only REMOVE an id when the fetched doc for that id explicitly says
// active:false — never because an id was merely absent from this page.
async function fetchConfirmedBleeds() {
  try {
    const docs = [];
    let pageToken = null;
    do {
      const qs = 'pageSize=200' + (pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : '');
      const res = await firestoreRequest('GET', `/confirmedBleeds?${qs}`);
      if (!res.ok) return; // leave serverConfirmedBleeds untouched on any read failure
      const data = await res.json();
      docs.push(...(data.documents || []));
      pageToken = data.nextPageToken || null;
    } while (pageToken);

    const next = { ...serverConfirmedBleeds };
    for (const doc of docs) {
      const f = doc.fields || {};
      const id = Number(doc.name.split('/').pop());
      const entry = {};
      for (const [k, v] of Object.entries(f)) entry[k] = fsRestVal(v);
      if (fsRestVal(f.active)) {
        next[id] = entry;       // confirmed active → add/refresh
      } else {
        delete next[id];        // confirmed inactive → remove
      }
      // Any id NOT present in `docs` at all is left exactly as-is in `next`;
      // we never infer "cleared" from mere absence in a single poll page.
    }

    const changed = JSON.stringify(next) !== JSON.stringify(serverConfirmedBleeds);
    if (changed) { serverConfirmedBleeds = next; broadcastBleeds(); }
  } catch (e) {
    console.warn('[bleeds] Firestore fallback poll error:', e.message);
  }
}

// ── Suspect / deduction / round-history: server-owned write + broadcast ──────
// Every open client independently *detects* these events from the same
// polled rankings data (that detection logic stays in the browser — it's
// tightly coupled to each client's own live round/peak-tracking state, so
// porting it server-side would be a much riskier rewrite). What changes is
// what a client does with something it detects: instead of writing straight
// to Firestore and opening an onSnapshot listener to see what everyone else
// wrote, it POSTs the event to the server. The server keeps a small in-memory
// cache, forwards only the FIRST report of any given id to Firestore, and
// broadcasts every real (non-duplicate) event to all connected clients over
// one shared SSE stream — the same pattern already used for confirmedBleeds
// above. N clients detecting the same real-world event now collapses into
// exactly one Firestore write and one fan-out, instead of N writes and
// N-times-listeners reads.

const TRACKER_CACHE_LIMITS = { suspects: 1000, deductions: 500, rounds: 100, bleedEvents: 500 };
const trackerCache = { suspects: [], deductions: [], rounds: [], bleedEvents: [] };
const trackerSeenKeys = { suspects: new Set(), deductions: new Set(), rounds: new Set() };
const trackerSseClients = new Set();

function broadcastTracker(type, entry) {
  const payload = `data: ${JSON.stringify({ type, entry })}\n\n`;
  for (const res of trackerSseClients) {
    try { res.write(payload); } catch { trackerSseClients.delete(res); }
  }
}

function capUnshift(arr, entry, limit) {
  arr.unshift(entry);
  if (arr.length > limit) arr.length = limit;
}

// Shared handler for the three auto-detected, high-frequency collections.
// Returns true if this was a genuinely new event (written through + broadcast).
async function ingestTrackerEvent(kind, collection, docId, entry, cacheKey) {
  const seen = trackerSeenKeys[cacheKey];
  if (seen.has(docId)) return false; // another client already reported this — no-op
  seen.add(docId);
  if (seen.size > 5000) { // keep the seen-set bounded on a long-running server
    seen.delete(seen.values().next().value);
  }
  capUnshift(trackerCache[cacheKey], entry, TRACKER_CACHE_LIMITS[cacheKey]);
  broadcastTracker(kind, entry);
  // Fire-and-forget write-through — the reporting client doesn't wait on this.
  firestoreRequest('PATCH', `/${collection}/${encodeURIComponent(docId)}`, fsDoc(entry))
    .then(res => { if (!res.ok) console.warn(`[tracker] ${collection} write failed: HTTP`, res.status); })
    .catch(e => console.warn(`[tracker] ${collection} write error:`, e.message));
  return true;
}

// One-time backfill on boot so the cache isn't empty for the first clients to
// connect after a deploy/restart. Runs ONCE regardless of how many clients
// connect afterward (they all just read this in-memory cache).
async function backfillTrackerCache() {
  async function fetchRecent(collection, orderField, limit) {
    try {
      return await firestoreRunQuery({
        from: [{ collectionId: collection }],
        orderBy: [{ field: { fieldPath: orderField }, direction: 'DESCENDING' }],
        limit,
      });
    } catch (e) {
      console.warn(`[tracker] backfill ${collection} failed:`, e.message);
      return [];
    }
  }
  const [suspects, deductions, rounds, bleedEvents] = await Promise.all([
    fetchRecent('suspectLog', 'ts', 200),
    fetchRecent('deductionLog', 'ts', 100),
    fetchRecent('roundHistory', 'endTs', 96),
    fetchRecent('bleedEventLog', 'ts', 100),
  ]);
  trackerCache.suspects   = suspects;
  trackerCache.deductions = deductions;
  trackerCache.rounds     = rounds.slice().sort((a, b) => new Date(a.startTs) - new Date(b.startTs));
  // The client dedupes bleedEventLog entries by `_id` (underscore) — that field
  // is only ever attached by the writing client at broadcast time, never by
  // this Firestore-backfill path, which only produces a bare `id`. Alias it
  // here so every entry the client sees carries the field it actually checks;
  // without this, every reconnect/reload re-added the whole cached log with
  // no way to recognize duplicates (bug: history showing each mark/clear 3x).
  trackerCache.bleedEvents = bleedEvents.map(e => ({ _id: e.id, ...e }));
  for (const s of suspects)   if (s.dedupKey) trackerSeenKeys.suspects.add(s.dedupKey);
  for (const d of deductions) trackerSeenKeys.deductions.add(`${d.clanId}_${d.ts}`);
  for (const r of rounds)     trackerSeenKeys.rounds.add(r.id);
}

// ── Express app ───────────────────────────────────────────────────────────────

const app = express();
app.use(express.json({ limit: '32kb' }));
app.use(express.static(__dirname, { etag: false }));

app.get('/api/push/public-key', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ publicKey });
});

app.post('/api/push/subscribe', async (req, res) => {
  const subscription = req.body;
  if (!subscription || typeof subscription.endpoint !== 'string' || !subscription.keys) {
    return res.status(400).json({ error: 'Invalid push subscription.' });
  }
  // Update in-memory list and both stores
  subscriptions = subscriptions.filter((item) => item.endpoint !== subscription.endpoint);
  subscriptions.push(subscription);
  writeJson(SUBSCRIPTIONS_FILE, subscriptions);
  saveSubscriptionToFirestore(subscription).catch(() => {}); // fire-and-forget
  res.status(201).json({ ok: true });
});

app.delete('/api/push/subscribe', async (req, res) => {
  const endpoint = req.body?.endpoint;
  subscriptions = subscriptions.filter((item) => item.endpoint !== endpoint);
  writeJson(SUBSCRIPTIONS_FILE, subscriptions);
  if (endpoint) removeSubscriptionFromFirestore(endpoint).catch(() => {}); // fire-and-forget
  res.json({ ok: true });
});

app.post('/api/push/confirmed', async (req, res) => {
  const clanName = typeof req.body?.clanName === 'string' ? req.body.clanName.trim() : '';
  const eventKey = typeof req.body?.eventKey === 'string' ? req.body.eventKey : Date.now().toString();
  if (!clanName) return res.status(400).json({ error: 'clanName is required.' });
  await sendPush({
    title: '🚨 Confirmed Bleeding',
    body: `The clan "${clanName}" is bleeding! Hurry up and attack!`,
    tag: `hidden-cloud-confirmed-bleeding-${eventKey}`,
  }, typeof req.body?.excludeEndpoint === 'string' ? req.body.excludeEndpoint : null, 600);
  res.json({ ok: true });
});

// Subscriber list — shows who is subscribed without sending anything
app.get('/api/push/subscribers', (_req, res) => {
  const list = subscriptions.map((s, i) => {
    const url = s.endpoint || '';
    let platform = 'Unknown';
    if (url.includes('fcm.googleapis.com'))        platform = 'Android / Chrome';
    else if (url.includes('web.push.apple.com'))   platform = 'iOS / Safari';
    else if (url.includes('notify.windows.com'))   platform = 'Windows / Edge';
    else if (url.includes('push.mozilla.com') || url.includes('updates.push.services.mozilla.com')) platform = 'Firefox';
    return { index: i + 1, platform, endpoint: url.slice(0, 80) + '…' };
  });
  res.json({ total: subscriptions.length, subscribers: list });
});

// Firebase client config — serves web SDK config so the API key never appears in index.html
app.get('/api/firebase-config', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({
    apiKey:            FIREBASE_API_KEY,
    authDomain:        `${FIREBASE_PROJECT}.firebaseapp.com`,
    projectId:         FIREBASE_PROJECT,
    storageBucket:     `${FIREBASE_PROJECT}.firebasestorage.app`,
    messagingSenderId: '354867534107',
    appId:             '1:354867534107:web:8452c807f24ef26dcedbbe',
  });
});

// Weekly gains — served from server memory (no Firestore reads).
// The server calculates gains from the live rankings API every 5 s and keeps
// the result in weeklyGainsState. Firestore is only written once per week
// (via archiveWeekToFirestore) when the week rolls over.
app.get('/api/weekly-gains', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  if (!weeklyGainsState.weekKey) {
    return res.json({ members: {}, lastUpdated: null, weekKey: null });
  }
  const membersObj = {};
  for (const [id, m] of Object.entries(weeklyGainsState.members)) {
    membersObj[id] = {
      name:         m.name,
      weekStartRep: m.weekStartRep,
      currentRep:   m.currentRep,
      weekGain:     Math.max(0, m.currentRep - m.weekStartRep),
    };
  }
  res.json({
    weekKey:        weeklyGainsState.weekKey,
    weekStartLabel: weeklyGainsState.weekStartLabel,
    weekEndLabel:   weeklyGainsState.weekEndLabel,
    weekIndex:      weeklyGainsState.weekIndex || null,
    weekStartTs:    weeklyGainsState.weekStartTs || null,
    weekEndTs:      weeklyGainsState.weekEndTs || null,
    seasonId:       weeklyGainsState.seasonId || null,
    seasonStartTs:  weeklyGainsState.seasonStartTs || null,
    seasonEndTs:    weeklyGainsState.seasonEndTs || null,
    seasonEnded:    !!(weeklyGainsState.seasonEndTs && Date.now() >= weeklyGainsState.seasonEndTs),
    members:        membersObj,
    lastUpdated:    Date.now(),
  });
});

// Discord bleed ping — proxied through the server so any logged-in member can
// trigger it regardless of their Firestore client-side read permissions.
// Webhook URL is disk-cached; server restart forces a fresh Firestore read.
app.post('/api/discord/bleed', async (req, res) => {
  const { clanName, clanRank, clanRep, action, byUser, timeStr } = req.body || {};
  if (!clanName || !action || !byUser) {
    return res.status(400).json({ ok: false, error: 'Missing required fields.' });
  }

  // Fetch webhook URL from cache (refreshed from Firestore at most every 5 min)
  const webhookUrl = await getDiscordWebhookUrl();

  if (!webhookUrl) {
    return res.status(200).json({ ok: false, error: 'No Discord webhook URL configured.' });
  }

  let content;
  if (action === 'marked') {
    content = `\u{1FA78} **@everyone** \u2014 **${clanName}** is confirmed bleeding!\nReputation: **${clanRep}** | Rank: **#${clanRank}** | Marked by **${byUser}** | ${timeStr}\n\n\uD83D\uDC4D React to **confirm** \u00B7 \uD83D\uDC4E React for **false alarm**`;
  } else {
    content = `\u2705 **${clanName}** bleed has been cleared by **${byUser}** | ${timeStr}`;
  }

  try {
    const discordRes = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    });
    if (!discordRes.ok) {
      const text = await discordRes.text();
      console.warn('Discord webhook returned', discordRes.status, text);
      return res.status(200).json({ ok: false, error: `Discord returned ${discordRes.status}` });
    }
    res.json({ ok: true });
  } catch (e) {
    console.warn('Discord webhook fetch error:', e.message);
    res.status(200).json({ ok: false, error: e.message });
  }
});

// SSE stream — clients subscribe here instead of opening a Firestore listener.
// On connect they immediately receive the current state; future changes are pushed.
app.get('/api/bleed-stream', (req, res) => {
  res.set({
    'Content-Type':    'text/event-stream',
    'Cache-Control':   'no-cache',
    'Connection':      'keep-alive',
    'X-Accel-Buffering': 'no', // disable nginx buffering when proxied
  });
  res.flushHeaders();
  res.write(`data: ${JSON.stringify(serverConfirmedBleeds)}\n\n`); // send current state immediately
  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
});

// Called by the client immediately after every Firestore bleed write so the
// server can broadcast the change without waiting for the 30 s fallback poll.
// The client sends the updated slice of state; the server merges and broadcasts.
app.post('/api/bleeds/sync', (req, res) => {
  const { bleeds } = req.body || {};
  if (bleeds && typeof bleeds === 'object') {
    const next = { ...serverConfirmedBleeds };
    for (const [id, data] of Object.entries(bleeds)) {
      const numId = Number(id);
      if (data === null || (data && data.active === false)) {
        delete next[numId];
      } else if (data && data.active) {
        next[numId] = data;
      }
    }
    serverConfirmedBleeds = next;
    broadcastBleeds();
  }
  res.json({ ok: true });
});

// ── Tracker channel: suspects / deductions / rounds / bleed-event log ────────
// Replaces the four per-client Firestore onSnapshot listeners + direct writes
// that used to live in index.html for these collections.

app.post('/api/suspects', async (req, res) => {
  const entry = req.body;
  if (!entry || typeof entry.dedupKey !== 'string' || !entry.dedupKey) {
    return res.status(400).json({ error: 'dedupKey is required.' });
  }
  const isNew = await ingestTrackerEvent('suspect', 'suspectLog', entry.dedupKey, entry, 'suspects');
  res.json({ ok: true, duplicate: !isNew });
});

app.post('/api/deductions', async (req, res) => {
  const entry = req.body;
  if (!entry || typeof entry.clanId === 'undefined' || typeof entry.ts !== 'number') {
    return res.status(400).json({ error: 'clanId and ts are required.' });
  }
  // entry.ts is a local Date.now() from whichever client detected the change
  // first, so it can differ by a few seconds between clients watching the
  // same real event. Bucket it into a 30 s window (well above normal
  // cross-client poll skew) so those near-simultaneous reports collapse into
  // one Firestore write, while a genuine repeat of the same deduction value
  // hours later still gets logged as its own entry.
  const bucket = Math.floor(entry.ts / 30000);
  const docId = `${entry.clanId}_${entry.deduction}_${bucket}`;
  const isNew = await ingestTrackerEvent('deduction', 'deductionLog', docId, entry, 'deductions');
  res.json({ ok: true, duplicate: !isNew });
});

app.post('/api/rounds', async (req, res) => {
  const entry = req.body;
  if (!entry || typeof entry.id !== 'string' || !entry.id) {
    return res.status(400).json({ error: 'id is required.' });
  }
  const isNew = await ingestTrackerEvent('round', 'roundHistory', entry.id, entry, 'rounds');
  res.json({ ok: true, duplicate: !isNew });
});

// bleedEventLog writes stay client-side (they're one-off admin button clicks,
// not auto-detected every poll, so they were never the source of duplicate
// writes — only the listener reading them was expensive). This endpoint just
// lets the server cache + broadcast what the client already wrote, mirroring
// /api/bleeds/sync above, so clients can drop their onSnapshot listener too.
app.post('/api/bleed-events', (req, res) => {
  const entry = req.body;
  if (!entry || typeof entry !== 'object') return res.status(400).json({ error: 'entry is required.' });
  if (entry._patchId) {
    const idx = trackerCache.bleedEvents.findIndex(e => e._id === entry._patchId);
    if (idx !== -1) trackerCache.bleedEvents[idx] = { ...trackerCache.bleedEvents[idx], ...entry };
  } else {
    capUnshift(trackerCache.bleedEvents, entry, TRACKER_CACHE_LIMITS.bleedEvents);
  }
  broadcastTracker('bleedEvent', entry);
  res.json({ ok: true });
});

// Catch-up snapshot for a newly opened session — served entirely from the
// in-memory cache, so opening/reloading the app costs zero Firestore reads
// no matter how many people do it at once.
app.get('/api/tracker-snapshot', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json(trackerCache);
});

// Live stream — one shared connection per client, no Firestore listener behind it.
app.get('/api/tracker-stream', (req, res) => {
  res.set({
    'Content-Type':      'text/event-stream',
    'Cache-Control':      'no-cache',
    'Connection':         'keep-alive',
    'X-Accel-Buffering':  'no',
  });
  res.flushHeaders();
  trackerSseClients.add(res);
  req.on('close', () => trackerSseClients.delete(res));
});

// Health check — used by UptimeRobot and for verifying the server is running
app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    subscribers: subscriptions.length,
    uptime: Math.floor(process.uptime()),
  });
});

// Test push — sends a real web push to all subscribers so you can verify
// the full pipeline (server → push service → device → service worker) works.
// Hit this from a browser or curl while the app is CLOSED on your device.
app.post('/api/push/test', async (req, res) => {
  if (subscriptions.length === 0) {
    return res.json({ ok: false, message: 'No subscribers stored. Open the app, enable notifications, then try again.' });
  }
  await sendPush({
    title: '🔔 Push Test',
    body: `Test push sent at ${new Date().toLocaleTimeString()} to ${subscriptions.length} subscriber(s). If you see this with the app closed, push is working!`,
    tag: `hidden-cloud-push-test-${Date.now()}`,
  });
  res.json({ ok: true, subscribers: subscriptions.length });
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, '0.0.0.0', async () => {
  console.log(`Hidden Cloud tracker listening on port ${PORT}`);
  await initSubscriptions();               // load push subs from Firestore
  await restoreWeeklyGainsFromFirestore(); // reconcile weekStartRep baselines with Firestore
  // Immediately push the reconciled state back so other instances see the best baselines.
  if (weeklyGainsState.weekKey && weeklyGainsWriteAllowed) {
    syncWeeklyGainsToFirestore().catch(e => console.warn('[weekly] Startup sync error:', e.message));
  }
  await fetchConfirmedBleeds();            // prime SSE state before first client connects
  setInterval(fetchConfirmedBleeds, CONFIRMED_BLEEDS_FALLBACK_POLL_MS); // 30 s fallback poll
  await backfillTrackerCache();            // prime suspects/deductions/rounds/bleed-log once
  pollForPossibleBleeding();
  setInterval(pollForPossibleBleeding, POLL_INTERVAL_MS);
});
