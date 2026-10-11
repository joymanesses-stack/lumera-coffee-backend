'use strict';

const path = require('node:path');
require('dotenv').config({ path: [path.resolve(__dirname, '../.env'), path.resolve(__dirname, '.env')] });
const { initializeApp, applicationDefault, getApp, getApps } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

const config = {
  port: Number(process.env.PORT || 3001),
  jwtSecret: process.env.JWT_SECRET || '',
  jwtTtl: Math.min(Math.max(Number(process.env.JWT_TTL_SECONDS || 86400), 300), 604800),
  // Keep the deployed storefront origins allowed even when Render's
  // ALLOWED_ORIGINS setting only contains local or staging URLs.
  origins: [...new Set([
    'https://lumera-coffee.com',
    'https://www.lumera-coffee.com',
    ...(process.env.ALLOWED_ORIGINS || '').split(',').map((value) => value.trim()).filter(Boolean),
  ])],
  adminEmails: (process.env.ADMIN_EMAILS || process.env.BOOTSTRAP_ADMIN_EMAIL || '').split(',').map((value) => value.trim().toLowerCase()).filter(Boolean),
  adminPassword: process.env.ADMIN_PASSWORD || '',
  stunUrls: (process.env.STUN_URLS || 'stun:stun.l.google.com:19302').split(',').map((value) => value.trim()).filter(Boolean),
  turnUrls: (process.env.TURN_URLS || '').split(',').map((value) => value.trim()).filter(Boolean),
  firebaseProjectId: process.env.FIREBASE_PROJECT_ID || process.env.VITE_FIREBASE_PROJECT_ID || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT || '',
  firestoreDatabaseId: process.env.FIRESTORE_DATABASE_ID || '(default)',
};

if (config.jwtSecret.length < 32) throw new Error('Set JWT_SECRET to a random value of at least 32 characters.');
if (!config.origins.length) throw new Error('Set ALLOWED_ORIGINS to the exact website origins allowed to use this API.');
if (getApps().length === 0) {
  initializeApp({ credential: applicationDefault(), ...(config.firebaseProjectId ? { projectId: config.firebaseProjectId } : {}) });
}

module.exports = { config, db: getFirestore(getApp(), config.firestoreDatabaseId), firebaseAuth: getAuth(), FieldValue };
