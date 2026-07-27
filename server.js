const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const path = require('path');
const webpush = require('web-push');

const PORT = Number(process.env.PORT || 5000);
const API_URL = 'https://static.ninjasaga.cc/data/clan_rankings.json';
const POLL_INTERVAL_MS = 2000;
const POSSIBLE_BLEEDING_CLAN_THRESHOLD = 2;
const POSSIBLE_BLEEDING_DELAY_MS = 10000;
const DATA_DIR = process.env.PUSH_DATA_DIR || path.join(__dirname, '.data');
const SUBSCRIPTIONS_FILE = path.join(DATA_DIR, 'push-subscriptions.json'); // local fallback
const DETECTOR_STATE_FILE = path.join(DATA_DIR, 'push-detector-state.json');
const FIREBASE_TOKEN_FILE = path.join(DATA_DIR, 'firebase-token.json');

// Firebase project config (same project the client already uses)
const FIREBASE_API_KEY = 'AIzaSyBt1VtMUsUd_pVOG6sKbCJTHS2bka8kVpo';
const FIREBASE_PROJECT = 'clantracker-22435';
const FIRESTORE_BASE =
  `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT}/databases/(default)/documents`;
const FIREBASE_AUTH_URL =
  `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${FIREBASE_API_KEY}`;
const FIREBASE_REFRESH_URL =
  `https://securetoken.googleapis.com/v1/token?key=${FIREBASE_API_KEY}`;

fs.mkdirSync(DATA_DIR, { recursive: true });

// ── Helpers ──────────────────────────────────────────────────────────────────

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

async function pollForPossibleBleeding() {
  try {
    const response = await fetch(API_URL, { cache: 'no-store' });
    if (!response.ok) throw new Error(`rankings HTTP ${response.status}`);
    const json = await response.json();
    const roundId = currentRoundId();
    if (detectorState.roundId !== roundId) {
      detectorState.roundId = roundId;
      detectorState.previous = null;
      detectorState.memberGainEvents = {};
      detectorState.possibleBleedSince = null;
      detectorState.possibleNotifiedRoundId = null;
    }

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
  await initSubscriptions(); // load from Firestore before polling starts
  pollForPossibleBleeding();
  setInterval(pollForPossibleBleeding, POLL_INTERVAL_MS);
});
