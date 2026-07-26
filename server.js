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
const SUBSCRIPTIONS_FILE = path.join(DATA_DIR, 'push-subscriptions.json');
const DETECTOR_STATE_FILE = path.join(DATA_DIR, 'push-detector-state.json');

fs.mkdirSync(DATA_DIR, { recursive: true });

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

let subscriptions = readJson(SUBSCRIPTIONS_FILE, []);
let detectorState = readJson(DETECTOR_STATE_FILE, {
  roundId: null,
  previous: null,
  memberGainEvents: {},
  possibleBleedSince: null,
  possibleNotifiedRoundId: null,
});

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

function currentRoundId(now = new Date()) {
  const round = new Date(now);
  round.setSeconds(0, 0);
  round.setMinutes(round.getMinutes() < 30 ? 0 : 30);
  return round.toISOString();
}

function sendPush(payload, excludeEndpoint = null) {
  const body = JSON.stringify({
    ...payload,
    icon: './pwa-icon-192.png',
    badge: './pwa-icon-192.png',
  });
  const sends = subscriptions.map(async (subscription) => {
    if (subscription.endpoint === excludeEndpoint) return subscription;
    try {
      await webpush.sendNotification(subscription, body);
      return subscription;
    } catch (error) {
      if (error.statusCode === 404 || error.statusCode === 410) return null;
      console.warn('Push delivery failed:', error.statusCode || error.message);
      return subscription;
    }
  });
  return Promise.all(sends).then((remaining) => {
    subscriptions = remaining.filter(Boolean);
    writeJson(SUBSCRIPTIONS_FILE, subscriptions);
  });
}

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

const app = express();
app.use(express.json({ limit: '32kb' }));
app.use(express.static(__dirname, { etag: false }));

app.get('/api/push/public-key', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ publicKey });
});

app.post('/api/push/subscribe', (req, res) => {
  const subscription = req.body;
  if (!subscription || typeof subscription.endpoint !== 'string' || !subscription.keys) {
    return res.status(400).json({ error: 'Invalid push subscription.' });
  }
  subscriptions = subscriptions.filter((item) => item.endpoint !== subscription.endpoint);
  subscriptions.push(subscription);
  writeJson(SUBSCRIPTIONS_FILE, subscriptions);
  res.status(201).json({ ok: true });
});

app.delete('/api/push/subscribe', (req, res) => {
  subscriptions = subscriptions.filter((item) => item.endpoint !== req.body?.endpoint);
  writeJson(SUBSCRIPTIONS_FILE, subscriptions);
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
  }, typeof req.body?.excludeEndpoint === 'string' ? req.body.excludeEndpoint : null);
  res.json({ ok: true });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Hidden Cloud tracker listening on port ${PORT}`);
  pollForPossibleBleeding();
  setInterval(pollForPossibleBleeding, POLL_INTERVAL_MS);
});