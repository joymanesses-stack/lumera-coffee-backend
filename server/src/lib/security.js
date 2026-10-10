'use strict';

const crypto = require('node:crypto');
const { db, firebaseAuth, config } = require('../config');
const { httpError } = require('./errors');

const users = db.collection('backendUsers');
const agents = db.collection('backendAgents');
const admins = db.collection('backendAdmins');

function isConfiguredAdmin(email, emailVerified) {
  return emailVerified === true && typeof email === 'string' && config.adminEmails.includes(email.trim().toLowerCase());
}

function tokenFor(user) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ sub: user.uid, role: user.role, email: user.email || null, iat: now, exp: now + config.jwtTtl })).toString('base64url');
  const content = `${header}.${payload}`;
  return `${content}.${crypto.createHmac('sha256', config.jwtSecret).update(content).digest('base64url')}`;
}

function verifyLocalToken(token) {
  const [header, payload, signature, extra] = token.split('.');
  if (!header || !payload || !signature || extra) throw httpError(401, 'Invalid session token.');
  const expected = crypto.createHmac('sha256', config.jwtSecret).update(`${header}.${payload}`).digest();
  const actual = Buffer.from(signature, 'base64url');
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) throw httpError(401, 'Invalid session token.');
  let claims;
  try { claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); } catch { throw httpError(401, 'Invalid session token.'); }
  if (!claims.sub || !['customer', 'agent', 'admin'].includes(claims.role) || claims.exp <= Math.floor(Date.now() / 1000)) throw httpError(401, 'Session is expired or invalid.');
  return { uid: claims.sub, role: claims.role, email: claims.email || null, provider: 'backend' };
}

async function authenticateToken(token) {
  try {
    const user = verifyLocalToken(token);
    const collection = user.role === 'admin' ? admins : user.role === 'agent' ? agents : users;
    const snapshot = await collection.doc(user.uid).get();
    if (!snapshot.exists) throw httpError(401, 'Session is no longer valid.');
    if (snapshot.exists && snapshot.data().active === false) throw httpError(403, 'This account is disabled.');
    return user;
  } catch (error) { if (error.status !== 401) throw error; }
  try {
    const decoded = await firebaseAuth.verifyIdToken(token, true);
    if (decoded.firebase?.sign_in_provider === 'anonymous') throw httpError(401, 'Sign in with a customer account before using the call center.');
    const [admin, agent, legacyAgent, pluralAgent] = await Promise.all([
      admins.doc(decoded.uid).get(), agents.doc(decoded.uid).get(),
      db.collection('agent').doc(decoded.uid).get(), db.collection('agents').doc(decoded.uid).get(),
    ]);
    if (admin.exists && admin.data().active !== true) throw httpError(403, 'This administrator account is disabled.');
    if ([agent, legacyAgent, pluralAgent].some((entry) => entry.exists && entry.data().active !== true)) throw httpError(403, 'This agent account is disabled.');
    const role = isConfiguredAdmin(decoded.email, decoded.email_verified) || (admin.exists && admin.data().active === true) ? 'admin'
      : [agent, legacyAgent, pluralAgent].some((entry) => entry.exists && entry.data().active === true) ? 'agent' : 'customer';
    if (role === 'customer') {
      const userSnapshot = await users.doc(decoded.uid).get();
      if (userSnapshot.exists && userSnapshot.data().active === false) throw httpError(403, 'This account is disabled.');
    }
    return { uid: decoded.uid, role, email: decoded.email || null, provider: 'firebase' };
  } catch (error) {
    if (error.status) throw error;
    throw httpError(401, 'Sign in with a valid backend session or Firebase ID token.');
  }
}

async function authMiddleware(request, response, next) {
  try {
    const match = /^Bearer\s+(.+)$/i.exec(request.headers.authorization || '');
    if (!match) throw httpError(401, 'Bearer authentication is required.');
    request.user = await authenticateToken(match[1]);
    next();
  } catch (error) { next(error); }
}

function requireRole(...roles) {
  return (request, response, next) => request.user && roles.includes(request.user.role)
    ? next() : next(httpError(403, 'This account is not allowed to perform that action.'));
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(password, salt, 64).toString('hex') };
}

function passwordMatches(password, stored) {
  if (!stored || typeof stored.salt !== 'string' || typeof stored.hash !== 'string') return false;
  const actual = crypto.scryptSync(password, stored.salt, 64);
  const expected = Buffer.from(stored.hash, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

const normalizeEmail = (email) => typeof email === 'string' ? email.trim().toLowerCase() : '';
const emailId = (email) => crypto.createHash('sha256').update(email).digest('hex');
const validPassword = (password) => typeof password === 'string' && password.length >= 10 && password.length <= 128;
const publicUser = (user) => ({ id: user.uid, email: user.email || null, role: user.role });
const issueSession = (user) => ({ token: tokenFor(user), tokenType: 'Bearer', expiresIn: config.jwtTtl, user: publicUser(user) });

module.exports = { users, agents, admins, authMiddleware, requireRole, authenticateToken, hashPassword, passwordMatches, normalizeEmail, emailId, validPassword, publicUser, issueSession, isConfiguredAdmin };
