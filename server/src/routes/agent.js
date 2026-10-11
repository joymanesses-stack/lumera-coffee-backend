'use strict';

const express = require('express');
const { db, FieldValue, firebaseAuth } = require('../config');
const { asyncRoute, httpError } = require('../lib/errors');
const { authMiddleware, requireRole, users } = require('../lib/security');

const router = express.Router();
const auditLogs = db.collection('auditLogs');
const calls = db.collection('calls');

async function withCallerDetails(call) {
  const caller = {
    name: call.callerName || call.callerEmail || 'Customer',
    email: call.callerEmail || null,
    phone: call.callerPhone || null,
  };
  try {
    const user = await firebaseAuth.getUser(call.callerUid);
    caller.name = user.displayName || user.email || user.phoneNumber || caller.name;
    caller.email = user.email || caller.email;
    caller.phone = user.phoneNumber || caller.phone;
  } catch { /* Backend-managed callers may not have a Firebase Auth profile. */ }
  if (call.callerUid) {
    const profile = await users.doc(call.callerUid).get();
    if (profile.exists) {
      caller.email = caller.email || profile.data().email || null;
      caller.name = profile.data().displayName || caller.name;
      caller.phone = caller.phone || profile.data().phone || profile.data().phoneNumber || null;
    }
  }
  if (caller.name === 'Customer' && caller.email) caller.name = caller.email;
  return { ...call, callerName: caller.name, callerEmail: caller.email, callerPhone: caller.phone, caller };
}

router.get('/bin/calls', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (_request, response) => {
  const [snapshot, legacySnapshot] = await Promise.all([
    calls.where('inBin', '==', true).get(),
    calls.where('deletedAt', '!=', null).get(),
  ]);
  const uniqueDocs = new Map([...snapshot.docs, ...legacySnapshot.docs].map((doc) => [doc.id, doc]));
  const docs = [...uniqueDocs.values()].filter((doc) => doc.data().inBin === true || doc.data().deletedAt)
    .sort((left, right) => (right.data().deletedAt?.toMillis?.() || 0) - (left.data().deletedAt?.toMillis?.() || 0)).slice(0, 100);
  const binnedCalls = await Promise.all(docs.map((doc) => withCallerDetails({ id: doc.id, ...doc.data() })));
  response.json({ calls: binnedCalls });
}));

router.delete('/calls/:callId', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (request, response) => {
  const ref = calls.doc(request.params.callId);
  const result = await db.runTransaction(async (transaction) => {
    const snapshot = await transaction.get(ref);
    if (!snapshot.exists) throw httpError(404, 'Call not found.');
    const call = snapshot.data();
    if (call.inBin === true) return { alreadyInBin: true };
    if (call.deletedAt) {
      transaction.update(ref, { inBin: true });
      return { alreadyInBin: true };
    }
    if (!['missed', 'declined', 'ended'].includes(call.status)) throw httpError(409, 'Only completed calls can be moved to Bin.');
    transaction.update(ref, { inBin: true, deletedAt: FieldValue.serverTimestamp(), deletedBy: request.user.uid });
    return { alreadyInBin: false };
  });
  if (!result.alreadyInBin) {
    await auditLogs.add({ action: 'call.soft_delete', callId: ref.id, actorUid: request.user.uid, createdAt: FieldValue.serverTimestamp() });
  }
  response.json({ deleted: true, id: ref.id, alreadyInBin: result.alreadyInBin });
}));

router.post('/bin/calls/:callId/restore', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (request, response) => {
  const ref = calls.doc(request.params.callId);
  const restored = await db.runTransaction(async (transaction) => {
    const snapshot = await transaction.get(ref);
    if (!snapshot.exists || (snapshot.data().inBin !== true && !snapshot.data().deletedAt)) throw httpError(404, 'Deleted call not found in Bin.');
    const call = snapshot.data();
    transaction.update(ref, {
      inBin: false, deletedAt: FieldValue.delete(), deletedBy: FieldValue.delete(),
      deletedPreviousStatus: FieldValue.delete(), restoredAt: FieldValue.serverTimestamp(), restoredBy: request.user.uid,
    });
    return { id: ref.id, ...call, inBin: false, deletedAt: null, deletedBy: null };
  });
  await auditLogs.add({ action: 'call.restore', callId: ref.id, actorUid: request.user.uid, createdAt: FieldValue.serverTimestamp() });
  response.json({ restored: true, call: restored });
}));

router.delete('/bin/calls/:callId', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (request, response) => {
  const ref = calls.doc(request.params.callId);
  await db.runTransaction(async (transaction) => {
    const snapshot = await transaction.get(ref);
    if (!snapshot.exists || (snapshot.data().inBin !== true && !snapshot.data().deletedAt)) throw httpError(404, 'Deleted call not found in Bin.');
    transaction.delete(ref);
  });
  await auditLogs.add({ action: 'call.permanent_delete', callId: ref.id, actorUid: request.user.uid, createdAt: FieldValue.serverTimestamp() });
  response.json({ deleted: true, id: ref.id });
}));

router.get('/customers', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (_request, response) => {
  const snapshot = await users.limit(200).get();
  const customers = await Promise.all(snapshot.docs.map(async (doc) => {
    const value = doc.data();
    let displayName = value.displayName || null;
    if (!doc.id.startsWith('local_')) {
      try { displayName = (await firebaseAuth.getUser(doc.id)).displayName || displayName; }
      catch { /* Keep the profile stored by the backend when Firebase has no user. */ }
    }
    return { uid: value.uid || doc.id, email: value.email || null, displayName, active: value.active !== false, deletedAt: value.deletedAt || null };
  }));
  response.json({ customers: customers.filter((customer) => !customer.deletedAt) });
}));

router.delete('/customers/:uid', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (request, response) => {
  const uid = request.params.uid;
  const ref = users.doc(uid);
  const snapshot = await ref.get();
  if (!snapshot.exists || snapshot.data().role !== 'customer') throw httpError(404, 'Customer account not found.');
  if (snapshot.data().active === false) throw httpError(409, 'This customer account is already disabled.');

  try {
    await firebaseAuth.updateUser(uid, { disabled: true });
    await firebaseAuth.revokeRefreshTokens(uid);
  } catch (error) {
    if (error.code !== 'auth/user-not-found') throw error;
  }

  await ref.update({ active: false, deletedAt: FieldValue.serverTimestamp(), deletedBy: request.user.uid, updatedAt: FieldValue.serverTimestamp() });
  await auditLogs.add({ action: 'customer.account.soft_delete', targetUid: uid, actorUid: request.user.uid, createdAt: FieldValue.serverTimestamp() });
  response.json({ deleted: true, uid });
}));

module.exports = router;
