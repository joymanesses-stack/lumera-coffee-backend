'use strict';

const express = require('express');
const { FieldValue, db, firebaseAuth } = require('../config');
const { httpError, asyncRoute } = require('../lib/errors');
const { authMiddleware, requireRole, agents, admins, users, hashPassword, normalizeEmail, emailId, validPassword, isConfiguredAdmin } = require('../lib/security');

const router = express.Router();
const docs = (snapshot) => snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
const hidePassword = ({ password, ...record }) => record;
const dateValue = (value) => value?.toDate ? value.toDate().toISOString() : value?.toISOString ? value.toISOString() : value || null;
const publicRecord = (doc) => {
  const { password, ...record } = doc.data();
  return { id: doc.id, ...record, createdAt: dateValue(record.createdAt), updatedAt: dateValue(record.updatedAt) };
};

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

router.delete('/agents/:agentId', asyncRoute(async (request, response) => {
  const id = request.params.agentId;
  const ref = agents.doc(id);
  const snapshot = await ref.get();
  if (!snapshot.exists) throw httpError(404, 'Agent not found.');
  if (snapshot.data().deletedAt) return response.json({ deleted: true, id, alreadyInBin: true });
  const [assignedInquiries, activeConversations, activeCalls] = await Promise.all([
    db.collection('inquiries').where('assignedAgentUid', '==', id).get(),
    db.collection('conversations').where('agentUid', '==', id).get(),
    db.collection('calls').where('agentUid', '==', id).get(),
  ]);
  if (assignedInquiries.docs.some((doc) => !doc.data().deletedAt && doc.data().status !== 'closed')
    || activeConversations.docs.some((doc) => doc.data().status === 'active')
    || activeCalls.docs.some((doc) => doc.data().status === 'accepted')) {
    throw httpError(409, 'Reassign this agent’s open inquiries and finish active calls or chats before moving the account to Bin.');
  }
  await ref.update({ active: false, deletedAt: FieldValue.serverTimestamp(), deletedBy: request.user.uid, deletedPreviousActive: snapshot.data().active !== false });
  await db.collection('auditLogs').add({ action: 'agent.soft_delete', agentUid: id, actorUid: request.user.uid, createdAt: FieldValue.serverTimestamp() });
  response.json({ deleted: true, id });
}));

router.get('/bin/agents', asyncRoute(async (_request, response) => {
  const snapshot = await agents.where('deletedAt', '!=', null).orderBy('deletedAt', 'desc').limit(100).get();
  response.json({ agents: docs(snapshot).map(hidePassword) });
}));

router.post('/bin/agents/:agentId/restore', asyncRoute(async (request, response) => {
  const ref = agents.doc(request.params.agentId);
  const snapshot = await ref.get();
  if (!snapshot.exists || !snapshot.data().deletedAt) throw httpError(404, 'Deleted agent not found in Bin.');
  const value = snapshot.data();
  const active = value.deletedPreviousActive !== false;
  await ref.update({ active, deletedAt: FieldValue.delete(), deletedBy: FieldValue.delete(), deletedPreviousActive: FieldValue.delete(), restoredAt: FieldValue.serverTimestamp(), restoredBy: request.user.uid });
  await db.collection('auditLogs').add({ action: 'agent.restore', agentUid: ref.id, actorUid: request.user.uid, createdAt: FieldValue.serverTimestamp() });
  response.json({ restored: true, agent: hidePassword({ id: ref.id, ...value, active, deletedAt: null }) });
}));

router.delete('/bin/agents/:agentId', asyncRoute(async (request, response) => {
  const ref = agents.doc(request.params.agentId);
  const snapshot = await ref.get();
  if (!snapshot.exists || !snapshot.data().deletedAt) throw httpError(404, 'Deleted agent not found in Bin.');
  const [assignedInquiries, activeConversations, activeCalls] = await Promise.all([
    db.collection('inquiries').where('assignedAgentUid', '==', ref.id).get(),
    db.collection('conversations').where('agentUid', '==', ref.id).get(),
    db.collection('calls').where('agentUid', '==', ref.id).get(),
  ]);
  if (assignedInquiries.docs.some((doc) => !doc.data().deletedAt && doc.data().status !== 'closed')
    || activeConversations.docs.some((doc) => doc.data().status === 'active')
    || activeCalls.docs.some((doc) => doc.data().status === 'accepted')) {
    throw httpError(409, 'Reassign this agent’s open inquiries and finish active calls or chats before permanent deletion.');
  }
  try { await firebaseAuth.deleteUser(ref.id); }
  catch (error) { if (error.code !== 'auth/user-not-found') throw error; }
  await ref.delete();
  await db.collection('auditLogs').add({ action: 'agent.permanent_delete', agentUid: ref.id, actorUid: request.user.uid, createdAt: FieldValue.serverTimestamp() });
  response.json({ deleted: true, id: ref.id });
}));

router.get('/users', asyncRoute(async (request, response) => {
  const limit = Math.min(Math.max(Number(request.query.limit || 50), 1), 200);
  const snapshot = await users.limit(limit).get();
  response.json({ users: docs(snapshot).map(({ password, ...user }) => user) });
}));

router.get('/users/:userId', asyncRoute(async (request, response) => {
  const uid = request.params.userId;
  const [userSnapshot, agentSnapshot, adminSnapshot] = await Promise.all([
    users.doc(uid).get(), agents.doc(uid).get(), admins.doc(uid).get(),
  ]);
  const profileSnapshot = userSnapshot.exists ? userSnapshot : agentSnapshot.exists ? agentSnapshot : adminSnapshot;
  let firebaseUser = null;
  try { firebaseUser = await firebaseAuth.getUser(uid); }
  catch (error) { if (error.code !== 'auth/user-not-found') throw error; }
  if (!profileSnapshot.exists && !firebaseUser) throw httpError(404, 'User not found.');

  const profile = profileSnapshot.exists ? publicRecord(profileSnapshot) : {};
  const role = profile.role || (firebaseUser?.customClaims?.admin ? 'admin' : firebaseUser?.customClaims?.agent ? 'agent' : 'customer');
  const email = firebaseUser?.email || profile.email || null;
  const [callerCalls, agentCalls, assignedInquiries, emailInquiries, customerChats, legacyCustomerChats, agentChats] = await Promise.all([
    db.collection('calls').where('callerUid', '==', uid).limit(25).get(),
    db.collection('calls').where('agentUid', '==', uid).limit(25).get(),
    db.collection('inquiries').where('assignedAgentUid', '==', uid).limit(25).get(),
    email ? db.collection('inquiries').where('email', '==', email).limit(25).get() : Promise.resolve({ docs: [] }),
    db.collection('conversations').where('customerUid', '==', uid).limit(25).get(),
    db.collection('conversations').where('userUid', '==', uid).limit(25).get(),
    db.collection('conversations').where('agentUid', '==', uid).limit(25).get(),
  ]);
  const uniqueRecords = (...snapshots) => [...new Map(snapshots.flatMap((snapshot) => snapshot.docs).map((doc) => [doc.id, publicRecord(doc)])).values()];
  const newestFirst = (records) => records.sort((left, right) => (Date.parse(dateValue(right.createdAt)) || 0) - (Date.parse(dateValue(left.createdAt)) || 0));
  response.json({
    user: {
      uid, email, displayName: firebaseUser?.displayName || profile.displayName || email || uid,
      phoneNumber: firebaseUser?.phoneNumber || profile.phoneNumber || profile.phone || null,
      emailVerified: firebaseUser?.emailVerified ?? null,
      disabled: firebaseUser?.disabled ?? profile.active === false,
      role, provider: firebaseUser?.providerData?.map((item) => item.providerId) || profile.provider || null,
      createdAt: firebaseUser?.metadata?.creationTime || dateValue(profile.createdAt),
      lastSignInAt: firebaseUser?.metadata?.lastSignInTime || null,
      updatedAt: dateValue(profile.updatedAt),
    },
    calls: newestFirst(uniqueRecords(callerCalls, agentCalls)).slice(0, 25),
    inquiries: newestFirst(uniqueRecords(assignedInquiries, emailInquiries)).slice(0, 25),
    conversations: newestFirst(uniqueRecords(customerChats, legacyCustomerChats, agentChats)).slice(0, 25),
  });
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
