require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Anthropic = require('@anthropic-ai/sdk');
const { google } = require('googleapis');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');

const app = express();
app.use(cors());
app.use(express.json());

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});

// --- قراءة مفتاح الخدمة من متغير البيئة (وليس ملف) ---
const fs = require('fs');
const serviceAccount = JSON.parse(fs.readFileSync('/etc/secrets/service-account.json', 'utf8'));

// --- إعداد Firebase Admin (لتحديث Firestore بعد التحقق) ---
initializeApp({
  credential: cert(serviceAccount)
});
const db = getFirestore();

// --- إعداد Google Play Developer API ---
const androidPublisherAuth = new google.auth.GoogleAuth({
  credentials: serviceAccount,
  scopes: ['https://www.googleapis.com/auth/androidpublisher']
});const androidpublisher = google.androidpublisher({
  version: 'v3',
  auth: androidPublisherAuth
});

const PACKAGE_NAME = 'com.salehlharthy.tutortrack';

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

    const result = await androidpublisher.purchases.subscriptions.get({
      packageName: PACKAGE_NAME,
      subscriptionId: productId,
      token: purchaseToken
    });

    const purchase = result.data;
    const expiresAtMillis = parseInt(purchase.expiryTimeMillis, 10);
    const isValid = expiresAtMillis > Date.now();

    if (!isValid) {
      return res.json({ success: false, error: 'الاشتراك منتهي الصلاحية' });
    }

    // تحديث Firestore مباشرة من الخادم (آمن، لا يمر عبر التطبيق)
    await db.collection('families').doc(familyId).update({
      subscriptionStatus: 'premium',
      subscriptionExpiresAt: expiresAtMillis,
      subscriptionProductId: productId
    });

    res.json({ success: true, expiresAt: expiresAtMillis });
  } catch (error) {
    console.error('خطأ في التحقق من الشراء:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));