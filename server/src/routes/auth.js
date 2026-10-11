'use strict';

const express = require('express');
const crypto = require('node:crypto');
const { db, firebaseAuth, FieldValue, config } = require('../config');
const { httpError, asyncRoute } = require('../lib/errors');
const { users, agents, admins, authMiddleware, normalizeEmail, emailId, validPassword, hashPassword, passwordMatches, issueSession, publicUser, isConfiguredAdmin } = require('../lib/security');

const router = express.Router();

function matchesConfiguredPassword(candidate, expected) {
  if (typeof candidate !== 'string' || typeof expected !== 'string' || !expected) return false;
  const actual = Buffer.from(candidate);
  const configured = Buffer.from(expected);
  return actual.length === configured.length && crypto.timingSafeEqual(actual, configured);
}

router.post('/admin-login', asyncRoute(async (request, response) => {
  const email = normalizeEmail(request.body?.email);
  const password = request.body?.password;
  if (!config.adminEmails.includes(email) || !matchesConfiguredPassword(password, config.adminPassword)) {
    throw httpError(401, 'Email or password is incorrect.');
  }

  const uid = `local_${emailId(email)}`;
  await admins.doc(uid).set({
    uid, email, role: 'admin', active: true, provider: 'environment',
    lastLoginAt: FieldValue.serverTimestamp(),
  }, { merge: true });
  response.json(issueSession({ uid, email, role: 'admin' }));
}));

router.post('/register', asyncRoute(async (request, response) => {
  const email = normalizeEmail(request.body?.email);
  const password = request.body?.password;
  if (!/^\S+@\S+\.\S+$/.test(email)) throw httpError(400, 'Enter a valid email address.');
  if (!validPassword(password)) throw httpError(400, 'Password must contain 10 to 128 characters.');
  const ref = users.doc(emailId(email));
  await db.runTransaction(async (transaction) => {
    if ((await transaction.get(ref)).exists) throw httpError(409, 'An account with this email already exists.');
    transaction.create(ref, { uid: ref.id, email, role: 'customer', password: hashPassword(password), active: true, createdAt: FieldValue.serverTimestamp() });
  });
  response.status(201).json(issueSession({ uid: ref.id, email, role: 'customer' }));
}));

router.post('/login', asyncRoute(async (request, response) => {
  const email = normalizeEmail(request.body?.email);
  const password = request.body?.password;
  if (!email || typeof password !== 'string') throw httpError(400, 'Email and password are required.');
  const id = emailId(email);
  const [admin, agent, customer] = await Promise.all([admins.doc(`local_${id}`).get(), agents.doc(`local_${id}`).get(), users.doc(id).get()]);
  const entry = admin.exists ? admin.data() : agent.exists ? agent.data() : customer.data();
  const role = admin.exists ? 'admin' : agent.exists ? 'agent' : 'customer';
  if (!entry || entry.active === false || !passwordMatches(password, entry.password)) throw httpError(401, 'Email or password is incorrect.');
  response.json(issueSession({ uid: entry.uid || (role === 'customer' ? id : `local_${id}`), email, role }));
}));

router.post('/firebase', asyncRoute(async (request, response) => {
  const idToken = request.body?.idToken;
  if (typeof idToken !== 'string' || idToken.length > 10000) throw httpError(400, 'A Firebase ID token is required.');
  const decoded = await firebaseAuth.verifyIdToken(idToken, true);
  if (decoded.firebase?.sign_in_provider === 'anonymous') throw httpError(401, 'Sign in with a customer account before using the call center.');
  const [admin, agent, legacyAgent, pluralAgent] = await Promise.all([
    admins.doc(decoded.uid).get(), agents.doc(decoded.uid).get(),
    db.collection('agent').doc(decoded.uid).get(), db.collection('agents').doc(decoded.uid).get(),
  ]);
  const configuredAdmin = isConfiguredAdmin(decoded.email, decoded.email_verified);
  if (admin.exists && admin.data().active !== true && !configuredAdmin) throw httpError(403, 'This administrator account is disabled.');
  if ([agent, legacyAgent, pluralAgent].some((entry) => entry.exists && entry.data().active !== true)) throw httpError(403, 'This agent account is disabled.');
  const role = configuredAdmin || (admin.exists && admin.data().active === true) ? 'admin'
    : [agent, legacyAgent, pluralAgent].some((entry) => entry.exists && entry.data().active === true) ? 'agent' : 'customer';
  if (role === 'agent') {
    await agents.doc(decoded.uid).set({ uid: decoded.uid, email: decoded.email || null, role, active: true, provider: 'firebase', lastLoginAt: FieldValue.serverTimestamp() }, { merge: true });
  }
  if (role === 'admin') {
    await admins.doc(decoded.uid).set({ uid: decoded.uid, email: decoded.email || null, role, active: true, provider: 'firebase', lastLoginAt: FieldValue.serverTimestamp() }, { merge: true });
  }
  if (role === 'customer') {
    const userRef = users.doc(decoded.uid);
    const prior = await userRef.get();
    if (prior.exists && prior.data().active === false) throw httpError(403, 'This account is disabled.');
    await userRef.set({ uid: decoded.uid, email: decoded.email || null, role, provider: decoded.firebase?.sign_in_provider || 'firebase', active: true, lastLoginAt: FieldValue.serverTimestamp() }, { merge: true });
  }
  response.json(issueSession({ uid: decoded.uid, email: decoded.email || null, role }));
}));

router.get('/me', authMiddleware, (request, response) => response.json({ user: publicUser(request.user) }));

module.exports = router;
