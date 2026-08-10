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

const app = express();
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

// --- حماية من الإغراق بالطلبات (Rate Limiting) ---
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
    res.status(500).json({ error: error.message });
  }
});

// --- نقطة التحقق من صحة الاشتراك ---
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

    // تسجيل عملية الشراء في سجل منفصل لعرضه في لوحة الإدارة
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
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- حذف حساب عائلة بالكامل (Auth + كل بياناتها في Firestore) ---
app.post('/api/admin/delete-family', async (req, res) => {
  try {
    const { familyId, ownerUid } = req.body;
    if (!familyId || !ownerUid) {
      return res.status(400).json({ error: 'familyId and ownerUid are required' });
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));