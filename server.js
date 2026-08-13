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
  message: { error: 'تم تجاوز الحد المسموح من الطلبات. حاول لاحقاً.' },
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
    res.status(429).json({ error: 'تم تجاوز الحد المسموح من الطلبات. حاول لاحقاً.' });
  }
});
app.use('/api/', apiLimiter);
// --- Suspicious IP activity tracking (in-memory, resets on restart) ---
const ipActivityMap = new Map(); // ip -> { count, firstSeen }
const SUSPICIOUS_THRESHOLD = 20; // عدد الطلبات
const SUSPICIOUS_WINDOW_MS = 60 * 1000; // خلال دقيقة واحدة

app.use('/api/', async (req, res, next) => {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const entry = ipActivityMap.get(ip);

  if (!entry || now - entry.firstSeen > SUSPICIOUS_WINDOW_MS) {
    ipActivityMap.set(ip, { count: 1, firstSeen: now });
  } else {
    entry.count += 1;
    if (entry.count === SUSPICIOUS_THRESHOLD) {
      try {
        await db.collection('securityEvents').add({
          type: 'suspicious_ip',
          detail: `IP ${ip} أرسل ${SUSPICIOUS_THRESHOLD}+ طلب خلال دقيقة واحدة`,
          ip,
          createdAt: Date.now()
        });
      } catch (e) { console.error('Failed to log suspicious IP:', e); }
    }
  }
  next();
});

// تنظيف دوري للخريطة كل 5 دقائق لتفادي تسرب الذاكرة
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of ipActivityMap.entries()) {
    if (now - entry.firstSeen > SUSPICIOUS_WINDOW_MS) {
      ipActivityMap.delete(ip);
    }
  }
}, 5 * 60 * 1000);

// --- Track response time for every request ---
app.use('/api/', (req, res, next) => {
// --- Track response time for every request ---
app.use('/api/', (req, res, next) => {
  const startTime = Date.now();
  res.on('finish', async () => {
    const durationMs = Date.now() - startTime;
    try {
      await db.collection('performanceLogs').add({
        endpoint: req.path,
        durationMs,
        success: res.statusCode < 400,
        createdAt: Date.now()
      });
    } catch (e) {
      console.error('Failed to log performance:', e.message);
    }
  });
  next();
});

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
      return res.json({ success: false, error: 'الاشتراك منتهي الصلاحية' });
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
    console.error('خطأ في التحقق من الشراء:', error);
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
          detail: `طلب حذف عائلة بحقول ناقصة من IP: ${req.ip}`,
          ip: req.ip,
          createdAt: Date.now()
        });
      } catch (e) {}
      return res.status(400).json({ error: 'familyId and ownerUid are required' });
    }

    // تحقق أن العائلة موجودة فعلاً قبل محاولة الحذف (كشف محاولات عشوائية)
    const targetDoc = await db.collection('families').doc(familyId).get();
    if (!targetDoc.exists) {
      try {
        await db.collection('securityEvents').add({
          type: 'unauthorized_admin_access',
          detail: `محاولة حذف عائلة غير موجودة (familyId: ${familyId}) من IP: ${req.ip}`,
          ip: req.ip,
          createdAt: Date.now()
        });
      } catch (e) {}
      return res.status(404).json({ error: 'Family not found' });
    }
    try {
      await authAdmin.deleteUser(ownerUid);
    } catch (authErr) {
      console.error('تحذير: فشل حذف حساب Auth (قد يكون محذوفاً بالفعل):', authErr.message);
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
    console.error('خطأ في حذف العائلة:', error);
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
    console.error('فشل إرسال إشعار:', err.message);
  }
}

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}

// Daily teacher reminder - 8 PM Oman time
cron.schedule('0 16 * * *', async () => {
  console.log('تشغيل: تذكير المدرّسين اليومي');
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
          '📝 تذكير من TutorTrack',
          'لم تسجّل أي حصة اليوم بعد. لا تنسَ تسجيل حصصك!'
        );
      }
    }
  } catch (err) {
    console.error('خطأ في تذكير المدرّسين:', err.message);
  }
}, { timezone: 'Asia/Muscat' });

// Daily parent reminder - 9 PM Oman time
cron.schedule('0 17 * * *', async () => {
  console.log('تشغيل: تذكير أولياء الأمور اليومي');
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
          '🔔 تذكير من TutorTrack',
          `لديك ${pendingSnap.size} حصة بانتظار موافقتك`
        );
      }
    }
  } catch (err) {
    console.error('خطأ في تذكير أولياء الأمور:', err.message);
  }
}, { timezone: 'Asia/Muscat' });

// Weekly summary - Friday 6 PM Oman time
cron.schedule('0 14 * * 5', async () => {
  console.log('تشغيل: الملخص الأسبوعي');
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
          '📊 ملخصك الأسبوعي',
          `هذا الأسبوع: ${weekSessions.length} حصة بإجمالي ${total.toFixed(3)} ر.ع`
        );
      }
    }
  } catch (err) {
    console.error('خطأ في الملخص الأسبوعي:', err.message);
  }
}, { timezone: 'Asia/Muscat' });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));