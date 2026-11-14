require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const Anthropic = require('@anthropic-ai/sdk');
const { google } = require('googleapis');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const { getAuth } = require('firebase-admin/auth');
const fs = require('fs');
const cron = require('node-cron');

const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});

const serviceAccount = JSON.parse(fs.readFileSync('/etc/secrets/service-account.json', 'utf8'));

initializeApp({
  credential: cert(serviceAccount)
});
const db = getFirestore();
const authAdmin = getAuth();

const androidPublisherAuth = new google.auth.GoogleAuth({
  credentials: serviceAccount,
  scopes: ['https://www.googleapis.com/auth/androidpublisher']
});
const androidpublisher = google.androidpublisher({
  version: 'v3',
  auth: androidPublisherAuth
});

const PACKAGE_NAME = 'com.salehlharthy.tutortrack';

// --- Rate limiting protection ---
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'ØªÙ… ØªØ¬Ø§ÙˆØ² Ø§Ù„Ø­Ø¯ Ø§Ù„Ù…Ø³Ù…ÙˆØ­ Ù…Ù† Ø§Ù„Ø·Ù„Ø¨Ø§Øª. Ø­Ø§ÙˆÙ„ Ù„Ø§Ø­Ù‚Ø§Ù‹.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: async (req, res) => {
    try {
      await db.collection('securityEvents').add({
        type: 'rate_limit_exceeded',
        detail: `IP: ${req.ip} - Endpoint: ${req.path}`,
        createdAt: Date.now()
      });
    } catch (e) { console.error('Failed to log security event:', e); }
    res.status(429).json({ error: 'ØªÙ… ØªØ¬Ø§ÙˆØ² Ø§Ù„Ø­Ø¯ Ø§Ù„Ù…Ø³Ù…ÙˆØ­ Ù…Ù† Ø§Ù„Ø·Ù„Ø¨Ø§Øª. Ø­Ø§ÙˆÙ„ Ù„Ø§Ø­Ù‚Ø§Ù‹.' });
  }
});
app.use('/api/', apiLimiter);
// --- Suspicious IP activity tracking + auto-block (in-memory, resets on restart) ---
const ipActivityMap = new Map(); // ip -> { count, firstSeen }
const blockedIPs = new Map(); // ip -> blockedUntilTimestamp
const SUSPICIOUS_THRESHOLD = 20; // Ø¹Ø¯Ø¯ Ø§Ù„Ø·Ù„Ø¨Ø§Øª
const SUSPICIOUS_WINDOW_MS = 60 * 1000; // Ø®Ù„Ø§Ù„ Ø¯Ù‚ÙŠÙ‚Ø© ÙˆØ§Ø­Ø¯Ø©
const BLOCK_DURATION_MS = 30 * 60 * 1000; // 30 Ø¯Ù‚ÙŠÙ‚Ø© Ø­Ø¸Ø±

app.use('/api/', async (req, res, next) => {
  const ip = req.ip || 'unknown';
  const now = Date.now();

  // ØªØ­Ù‚Ù‚ Ø£ÙˆÙ„Ø§Ù‹: Ù‡Ù„ Ù‡Ø°Ø§ IP Ù…Ø­Ø¸ÙˆØ± Ø­Ø§Ù„ÙŠØ§Ù‹ØŸ
  const blockedUntil = blockedIPs.get(ip);
  if (blockedUntil && blockedUntil > now) {
    const minutesLeft = Math.ceil((blockedUntil - now) / 60000);
    return res.status(403).json({
      error: `ØªÙ… Ø­Ø¸Ø± Ù‡Ø°Ø§ Ø§Ù„Ø¹Ù†ÙˆØ§Ù† Ù…Ø¤Ù‚ØªØ§Ù‹ Ø¨Ø³Ø¨Ø¨ Ù†Ø´Ø§Ø· Ù…Ø´Ø¨ÙˆÙ‡. Ø­Ø§ÙˆÙ„ Ø¨Ø¹Ø¯ ${minutesLeft} Ø¯Ù‚ÙŠÙ‚Ø©.`
    });
  }
  if (blockedUntil && blockedUntil <= now) {
    blockedIPs.delete(ip); // Ø§Ù†ØªÙ‡Øª Ù…Ø¯Ø© Ø§Ù„Ø­Ø¸Ø±
  }

  const entry = ipActivityMap.get(ip);
  if (!entry || now - entry.firstSeen > SUSPICIOUS_WINDOW_MS) {
    ipActivityMap.set(ip, { count: 1, firstSeen: now });
  } else {
    entry.count += 1;
    if (entry.count === SUSPICIOUS_THRESHOLD) {
      // Ø­Ø¸Ø± ÙØ¹Ù„ÙŠ ØªÙ„Ù‚Ø§Ø¦ÙŠ
      blockedIPs.set(ip, now + BLOCK_DURATION_MS);
      try {
        await db.collection('securityEvents').add({
          type: 'suspicious_ip',
          detail: `ØªÙ… Ø­Ø¸Ø± IP ${ip} ØªÙ„Ù‚Ø§Ø¦ÙŠØ§Ù‹ Ù„Ù…Ø¯Ø© 30 Ø¯Ù‚ÙŠÙ‚Ø© Ø¨Ø¹Ø¯ Ø¥Ø±Ø³Ø§Ù„ ${SUSPICIOUS_THRESHOLD}+ Ø·Ù„Ø¨ Ø®Ù„Ø§Ù„ Ø¯Ù‚ÙŠÙ‚Ø© ÙˆØ§Ø­Ø¯Ø©`,
          ip,
          createdAt: Date.now()
        });
      } catch (e) { console.error('Failed to log suspicious IP:', e); }
      return res.status(403).json({
        error: 'ØªÙ… Ø­Ø¸Ø± Ù‡Ø°Ø§ Ø§Ù„Ø¹Ù†ÙˆØ§Ù† Ù…Ø¤Ù‚ØªØ§Ù‹ Ø¨Ø³Ø¨Ø¨ Ù†Ø´Ø§Ø· Ù…Ø´Ø¨ÙˆÙ‡. Ø­Ø§ÙˆÙ„ Ø¨Ø¹Ø¯ 30 Ø¯Ù‚ÙŠÙ‚Ø©.'
      });
    }
  }
  next();
});

// --- Ù†Ù‚Ø·Ø© Ù„Ø±ÙØ¹ Ø­Ø¸Ø± IP ÙŠØ¯ÙˆÙŠØ§Ù‹ Ù…Ù† Ù„ÙˆØ­Ø© Ø§Ù„Ø¥Ø¯Ø§Ø±Ø© ---
app.post('/api/admin/unblock-ip', async (req, res) => {
  try {
    const { ip } = req.body;
    if (!ip) {
      return res.status(400).json({ error: 'ip is required' });
    }
    blockedIPs.delete(ip);
    await db.collection('securityEvents').add({
      type: 'account_locked',
      detail: `ØªÙ… Ø±ÙØ¹ Ø­Ø¸Ø± IP ${ip} ÙŠØ¯ÙˆÙŠØ§Ù‹ Ù…Ù† Ù„ÙˆØ­Ø© Ø§Ù„Ø¥Ø¯Ø§Ø±Ø©`,
      ip,
      createdAt: Date.now()
    });
    res.json({ success: true });
  } catch (error) {
    console.error('Ø®Ø·Ø£ ÙÙŠ Ø±ÙØ¹ Ø§Ù„Ø­Ø¸Ø±:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});
// ØªÙ†Ø¸ÙŠÙ Ø¯ÙˆØ±ÙŠ Ù„Ø®Ø±ÙŠØ·ØªÙŠ Ø§Ù„ØªØªØ¨Ø¹ ÙˆØ§Ù„Ø­Ø¸Ø± ÙƒÙ„ 5 Ø¯Ù‚Ø§Ø¦Ù‚
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of ipActivityMap.entries()) {
    if (now - entry.firstSeen > SUSPICIOUS_WINDOW_MS) ipActivityMap.delete(ip);
  }
  for (const [ip, until] of blockedIPs.entries()) {
    if (until <= now) blockedIPs.delete(ip);
  }
}, 5 * 60 * 1000);
app.get('/', (req, res) => {
  res.json({ status: 'TutorTrack backend is running' });
});

app.post('/api/ask', async (req, res) => {
  try {
    const { system, messages } = req.body;
    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: 'messages array is required' });
    }
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 1024,
      system: system || '',
      messages: messages,
    });
    res.json({ content: response.content });
  } catch (error) {
    console.error(error);
    try {
      await db.collection('appErrors').add({
        type: 'network_error',
        message: error.message || 'Unknown error in /api/ask',
        screen: 'backend:/api/ask',
        userRole: 'unknown',
        familyId: null,
        createdAt: Date.now()
      });
    } catch (e) {}
    res.status(500).json({ error: error.message });
  }
});

// --- Verify subscription purchase ---
app.post('/api/verify-purchase', async (req, res) => {
  try {
    const { purchaseToken, productId, familyId } = req.body;
    if (!purchaseToken || !productId || !familyId) {
      return res.status(400).json({ error: 'purchaseToken, productId, and familyId are required' });
    }
    const result = await androidpublisher.purchases.subscriptionsv2.get({
      packageName: PACKAGE_NAME,
      token: purchaseToken
    });
    const purchase = result.data;
    const lineItem = purchase.lineItems?.[0];
    const expiresAtMillis = lineItem?.expiryTime
      ? new Date(lineItem.expiryTime).getTime()
      : 0;
    const isValid = expiresAtMillis > Date.now() &&
      (purchase.subscriptionState === 'SUBSCRIPTION_STATE_ACTIVE' ||
       purchase.subscriptionState === 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD');
    if (!isValid) {
      return res.json({ success: false, error: 'Ø§Ù„Ø§Ø´ØªØ±Ø§Ùƒ Ù…Ù†ØªÙ‡ÙŠ Ø§Ù„ØµÙ„Ø§Ø­ÙŠØ©' });
    }
    await db.collection('families').doc(familyId).update({
      subscriptionStatus: 'premium',
      subscriptionExpiresAt: expiresAtMillis,
      subscriptionProductId: productId
    });

    const familyDoc = await db.collection('families').doc(familyId).get();
    const familyData = familyDoc.exists ? familyDoc.data() : {};
    await db.collection('purchases').add({
      familyId,
      ownerEmail: familyData.ownerEmail || 'unknown',
      productId,
      purchaseToken,
      expiresAt: expiresAtMillis,
      purchasedAt: Date.now(),
      orderId: purchase.orderId || null
    });

    res.json({ success: true, expiresAt: expiresAtMillis });
  } catch (error) {
    console.error('Ø®Ø·Ø£ ÙÙŠ Ø§Ù„ØªØ­Ù‚Ù‚ Ù…Ù† Ø§Ù„Ø´Ø±Ø§Ø¡:', error);
    try {
      await db.collection('appErrors').add({
        type: 'purchase_error',
        message: error.message || 'Unknown purchase verification error',
        screen: 'backend:/api/verify-purchase',
        userRole: 'unknown',
        familyId: req.body?.familyId || null,
        createdAt: Date.now()
      });
    } catch (e) {}
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- Delete family account completely (Auth + all Firestore data) ---
app.post('/api/admin/delete-family', async (req, res) => {
  try {
    const { familyId, ownerUid } = req.body;
    if (!familyId || !ownerUid) {
      try {
        await db.collection('securityEvents').add({
          type: 'malformed_request',
          detail: `Ø·Ù„Ø¨ Ø­Ø°Ù Ø¹Ø§Ø¦Ù„Ø© Ø¨Ø­Ù‚ÙˆÙ„ Ù†Ø§Ù‚ØµØ© Ù…Ù† IP: ${req.ip}`,
          ip: req.ip,
          createdAt: Date.now()
        });
      } catch (e) {}
      return res.status(400).json({ error: 'familyId and ownerUid are required' });
    }

    // ØªØ­Ù‚Ù‚ Ø£Ù† Ø§Ù„Ø¹Ø§Ø¦Ù„Ø© Ù…ÙˆØ¬ÙˆØ¯Ø© ÙØ¹Ù„Ø§Ù‹ Ù‚Ø¨Ù„ Ù…Ø­Ø§ÙˆÙ„Ø© Ø§Ù„Ø­Ø°Ù (ÙƒØ´Ù Ù…Ø­Ø§ÙˆÙ„Ø§Øª Ø¹Ø´ÙˆØ§Ø¦ÙŠØ©)
    const targetDoc = await db.collection('families').doc(familyId).get();
    if (!targetDoc.exists) {
      try {
        await db.collection('securityEvents').add({
          type: 'unauthorized_admin_access',
          detail: `Ù…Ø­Ø§ÙˆÙ„Ø© Ø­Ø°Ù Ø¹Ø§Ø¦Ù„Ø© ØºÙŠØ± Ù…ÙˆØ¬ÙˆØ¯Ø© (familyId: ${familyId}) Ù…Ù† IP: ${req.ip}`,
          ip: req.ip,
          createdAt: Date.now()
        });
      } catch (e) {}
      return res.status(404).json({ error: 'Family not found' });
    }
    try {
      await authAdmin.deleteUser(ownerUid);
    } catch (authErr) {
      console.error('ØªØ­Ø°ÙŠØ±: ÙØ´Ù„ Ø­Ø°Ù Ø­Ø³Ø§Ø¨ Auth (Ù‚Ø¯ ÙŠÙƒÙˆÙ† Ù…Ø­Ø°ÙˆÙØ§Ù‹ Ø¨Ø§Ù„ÙØ¹Ù„):', authErr.message);
    }
    const collections = ['teachers', 'sessions', 'monthlyConfirmations', 'supportTickets'];
    for (const col of collections) {
      const snap = await db.collection(col).where('familyId', '==', familyId).get();
      const batch = db.batch();
      snap.docs.forEach((doc) => batch.delete(doc.ref));
      if (!snap.empty) await batch.commit();
    }
    await db.collection('families').doc(familyId).delete();
    res.json({ success: true });
  } catch (error) {
    console.error('Ø®Ø·Ø£ ÙÙŠ Ø­Ø°Ù Ø§Ù„Ø¹Ø§Ø¦Ù„Ø©:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

/* ---------------- Scheduled notifications ---------------- */

async function sendExpoPushNotification(pushToken, title, body) {
  if (!pushToken || !pushToken.startsWith('ExponentPushToken')) return;
  try {
    await fetch('https://exp.host/--/api/v2/push/send', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        to: pushToken,
        title,
        body,
        sound: 'default'
      })
    });
  } catch (err) {
    console.error('ÙØ´Ù„ Ø¥Ø±Ø³Ø§Ù„ Ø¥Ø´Ø¹Ø§Ø±:', err.message);
  }
}

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}

// Daily teacher reminder - 8 PM Oman time
cron.schedule('0 16 * * *', async () => {
  console.log('ØªØ´ØºÙŠÙ„: ØªØ°ÙƒÙŠØ± Ø§Ù„Ù…Ø¯Ø±Ù‘Ø³ÙŠÙ† Ø§Ù„ÙŠÙˆÙ…ÙŠ');
  try {
    const teachersSnap = await db.collection('teachers').where('status', '==', 'approved').get();
    const today = todayStr();
    for (const teacherDoc of teachersSnap.docs) {
      const teacher = teacherDoc.data();
      if (!teacher.pushToken) continue;
      const sessionsToday = await db.collection('sessions')
        .where('teacherId', '==', teacherDoc.id)
        .where('date', '==', today)
        .limit(1)
        .get();
      if (sessionsToday.empty) {
        await sendExpoPushNotification(
          teacher.pushToken,
          'ðŸ“ ØªØ°ÙƒÙŠØ± Ù…Ù† TutorTrack',
          'Ù„Ù… ØªØ³Ø¬Ù‘Ù„ Ø£ÙŠ Ø­ØµØ© Ø§Ù„ÙŠÙˆÙ… Ø¨Ø¹Ø¯. Ù„Ø§ ØªÙ†Ø³ÙŽ ØªØ³Ø¬ÙŠÙ„ Ø­ØµØµÙƒ!'
        );
      }
    }
  } catch (err) {
    console.error('Ø®Ø·Ø£ ÙÙŠ ØªØ°ÙƒÙŠØ± Ø§Ù„Ù…Ø¯Ø±Ù‘Ø³ÙŠÙ†:', err.message);
  }
}, { timezone: 'Asia/Muscat' });

// Daily parent reminder - 9 PM Oman time
cron.schedule('0 17 * * *', async () => {
  console.log('ØªØ´ØºÙŠÙ„: ØªØ°ÙƒÙŠØ± Ø£ÙˆÙ„ÙŠØ§Ø¡ Ø§Ù„Ø£Ù…ÙˆØ± Ø§Ù„ÙŠÙˆÙ…ÙŠ');
  try {
    const familiesSnap = await db.collection('families').get();
    for (const familyDoc of familiesSnap.docs) {
      const family = familyDoc.data();
      if (!family.pushToken) continue;
      const pendingSnap = await db.collection('sessions')
        .where('familyId', '==', familyDoc.id)
        .where('status', '==', 'pending')
        .get();
      if (pendingSnap.size > 0) {
        await sendExpoPushNotification(
          family.pushToken,
          'ðŸ”” ØªØ°ÙƒÙŠØ± Ù…Ù† TutorTrack',
          `Ù„Ø¯ÙŠÙƒ ${pendingSnap.size} Ø­ØµØ© Ø¨Ø§Ù†ØªØ¸Ø§Ø± Ù…ÙˆØ§ÙÙ‚ØªÙƒ`
        );
      }
    }
  } catch (err) {
    console.error('Ø®Ø·Ø£ ÙÙŠ ØªØ°ÙƒÙŠØ± Ø£ÙˆÙ„ÙŠØ§Ø¡ Ø§Ù„Ø£Ù…ÙˆØ±:', err.message);
  }
}, { timezone: 'Asia/Muscat' });

// Weekly summary - Friday 6 PM Oman time
cron.schedule('0 14 * * 5', async () => {
  console.log('ØªØ´ØºÙŠÙ„: Ø§Ù„Ù…Ù„Ø®Øµ Ø§Ù„Ø£Ø³Ø¨ÙˆØ¹ÙŠ');
  try {
    const familiesSnap = await db.collection('families').get();
    const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    for (const familyDoc of familiesSnap.docs) {
      const family = familyDoc.data();
      if (!family.pushToken) continue;
      const sessionsSnap = await db.collection('sessions')
        .where('familyId', '==', familyDoc.id)
        .where('status', 'in', ['approved', 'paid'])
        .get();
      const weekSessions = sessionsSnap.docs.filter((d) => {
        const s = d.data();
        return s.createdAt && s.createdAt >= weekAgo;
      });
      if (weekSessions.length > 0) {
        const total = weekSessions.reduce((sum, d) => {
          const s = d.data();
          return sum + (s.rate || 0) * (s.duration || 0);
        }, 0);
        await sendExpoPushNotification(
          family.pushToken,
          'ðŸ“Š Ù…Ù„Ø®ØµÙƒ Ø§Ù„Ø£Ø³Ø¨ÙˆØ¹ÙŠ',
          `Ù‡Ø°Ø§ Ø§Ù„Ø£Ø³Ø¨ÙˆØ¹: ${weekSessions.length} Ø­ØµØ© Ø¨Ø¥Ø¬Ù…Ø§Ù„ÙŠ ${total.toFixed(3)} Ø±.Ø¹`
        );
      }
    }
  } catch (err) {
    console.error('Ø®Ø·Ø£ ÙÙŠ Ø§Ù„Ù…Ù„Ø®Øµ Ø§Ù„Ø£Ø³Ø¨ÙˆØ¹ÙŠ:', err.message);
  }
}, { timezone: 'Asia/Muscat' });

const PORT = process.env.PORT || 3000;

app.post('/api/admin/broadcast-notification', async (req, res) => {
  const { adminSecret, title, body, segment } = req.body;
  if (adminSecret !== 'tt_admin_bc_24') return res.status(403).json({ error: 'Unauthorized' });
  try {
    const familiesSnap = await db.collection('families').get();
    const tokens = [];
    const now = Date.now();
    familiesSnap.forEach(doc => {
      const data = doc.data();
      if (!data.pushToken || data.banned) return;
      const isActive = data.subscriptionStatus === 'premium' && data.subscriptionExpiresAt > now;
      const isTrial = data.subscriptionStatus === 'trial';
      const isFree = !isActive && !isTrial;
      if (segment === 'premium' && !isActive) return;
      if (segment === 'trial' && !isTrial) return;
      if (segment === 'free' && !isFree) return;
      tokens.push(data.pushToken);
        db.collection('families').doc(doc.id).collection('notifications').add({ title, body, createdAt: Date.now(), read: false });
    });
    if (tokens.length === 0) return res.json({ sent: 0 });
    const messages = tokens.map(token => ({ to: token, title, body }));
    for (let i = 0; i < messages.length; i += 100) {
      await fetch('https://exp.host/--/api/v2/push/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(messages.slice(i, i + 100)),
      });
    }
    return res.json({ sent: tokens.length });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

