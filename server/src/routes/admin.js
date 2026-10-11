'use strict';

const express = require('express');
const { FieldValue, db } = require('../config');
const { httpError, asyncRoute } = require('../lib/errors');
const { authMiddleware, requireRole, agents, admins, users, hashPassword, normalizeEmail, emailId, validPassword, isConfiguredAdmin } = require('../lib/security');

const router = express.Router();
const docs = (snapshot) => snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
const hidePassword = ({ password, ...record }) => record;

module.exports = (io) => {
router.use(authMiddleware, requireRole('admin'));

router.get('/agents', asyncRoute(async (_request, response) => {
  const snapshot = await agents.limit(200).get();
  response.json({ agents: docs(snapshot).map(hidePassword) });
}));

router.post('/agents', asyncRoute(async (request, response) => {
  const email = normalizeEmail(request.body?.email);
  const password = request.body?.password;
  if (!/^\S+@\S+\.\S+$/.test(email)) throw httpError(400, 'Enter a valid email address.');
  if (!validPassword(password)) throw httpError(400, 'Agent password must contain 10 to 128 characters.');
  const id = `local_${emailId(email)}`;
  const ref = agents.doc(id);
  const alreadyExists = await ref.get();
  if (alreadyExists.exists) throw httpError(409, 'An agent with this email already exists.');
  const agent = { uid: id, email, role: 'agent', active: true, password: hashPassword(password), createdAt: FieldValue.serverTimestamp(), createdBy: request.user.uid };
  await ref.create(agent);
  const result = { id, ...agent, password: undefined };
  response.status(201).json({ agent: result });
}));

router.patch('/agents/:agentId', asyncRoute(async (request, response) => {
  if (typeof request.body?.active !== 'boolean') throw httpError(400, 'Set active to true or false.');
  const id = request.params.agentId;
  let ref = agents.doc(id);
  let snapshot = await ref.get();
  if (!snapshot.exists && !id.startsWith('local_')) {
    ref = db.collection('backendAgents').doc(id);
    snapshot = await ref.get();
  }
  if (!snapshot.exists) throw httpError(404, 'Agent not found.');
  await ref.update({ active: request.body.active, updatedAt: FieldValue.serverTimestamp(), updatedBy: request.user.uid });
  response.json({ agent: hidePassword({ id, ...snapshot.data(), active: request.body.active }) });
}));

router.get('/users', asyncRoute(async (request, response) => {
  const limit = Math.min(Math.max(Number(request.query.limit || 50), 1), 200);
  const snapshot = await users.limit(limit).get();
  response.json({ users: docs(snapshot).map(({ password, ...user }) => user) });
}));

router.get('/audit-logs', asyncRoute(async (request, response) => {
  const limit = Math.min(Math.max(Number(request.query.limit || 50), 1), 200);
  const snapshot = await db.collection('auditLogs').orderBy('createdAt', 'desc').limit(limit).get();
  response.json({ auditLogs: docs(snapshot) });
}));

router.patch('/users/:userId', asyncRoute(async (request, response) => {
  if (typeof request.body?.active !== 'boolean') throw httpError(400, 'Set active to true or false.');
  const ref = users.doc(request.params.userId);
  const snapshot = await ref.get();
  if (!snapshot.exists) throw httpError(404, 'User not found.');
  await ref.update({ active: request.body.active, updatedAt: FieldValue.serverTimestamp(), updatedBy: request.user.uid });
  response.json({ user: { id: snapshot.id, email: snapshot.data().email || null, role: snapshot.data().role, active: request.body.active } });
}));

router.patch('/users/:userId/role', asyncRoute(async (request, response) => {
  const { role } = request.body || {};
  if (!['customer', 'agent', 'admin'].includes(role)) throw httpError(400, 'Role must be customer, agent, or admin.');
  const id = request.params.userId;
  const [userSnapshot, agentSnapshot, adminSnapshot] = await Promise.all([users.doc(id).get(), agents.doc(id).get(), admins.doc(id).get()]);
  const existing = userSnapshot.exists ? userSnapshot.data() : agentSnapshot.exists ? agentSnapshot.data() : adminSnapshot.exists ? adminSnapshot.data() : null;
  if (!existing) throw httpError(404, 'User not found.');
  if (isConfiguredAdmin(existing.email, true) && role !== 'admin') throw httpError(409, 'The configured administrator cannot be demoted.');
  const target = role === 'admin' ? admins : role === 'agent' ? agents : users;
  const otherRefs = [users.doc(id), agents.doc(id), admins.doc(id)].filter((ref) => ref.path !== target.doc(id).path);
  await target.doc(id).set({ ...existing, uid: id, role, updatedAt: FieldValue.serverTimestamp(), updatedBy: request.user.uid }, { merge: true });
  await Promise.all(otherRefs.map((ref) => ref.delete()));
  response.json({ user: { uid: id, email: existing.email || null, displayName: existing.displayName || existing.email || '', role } });
}));

router.get('/calls', asyncRoute(async (request, response) => {
  const limit = Math.min(Math.max(Number(request.query.limit || 50), 1), 200);
  const query = typeof request.query.status === 'string'
    ? db.collection('calls').where('status', '==', request.query.status).orderBy('createdAt', 'desc')
    : db.collection('calls').orderBy('createdAt', 'desc');
  const snapshot = await query.limit(limit).get();
  response.json({ calls: docs({ docs: snapshot.docs.filter((doc) => doc.data().inBin !== true && !doc.data().deletedAt) }) });
}));

router.get('/conversations', asyncRoute(async (request, response) => {
  const limit = Math.min(Math.max(Number(request.query.limit || 50), 1), 200);
  const query = typeof request.query.status === 'string'
    ? db.collection('conversations').where('status', '==', request.query.status).orderBy('createdAt', 'desc')
    : db.collection('conversations').orderBy('createdAt', 'desc');
  response.json({ conversations: docs(await query.limit(limit).get()) });
}));

router.post('/calls/:callId/end', asyncRoute(async (request, response) => {
  const ref = db.collection('calls').doc(request.params.callId);
  const snapshot = await ref.get();
  if (!snapshot.exists) throw httpError(404, 'Call not found.');
  await ref.update({ status: 'ended', endedAt: FieldValue.serverTimestamp(), endedBy: request.user.uid });
  const call = { id: ref.id, ...snapshot.data(), status: 'ended' };
  io.to(`call:${ref.id}`).emit('call:updated', call);
  io.to('agents').emit('call:updated', call);
  response.json({ call });
}));

return router;
};
