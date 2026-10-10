'use strict';

const express = require('express');
const crypto = require('node:crypto');
const { db, FieldValue, firebaseAuth } = require('../config');
const { httpError, asyncRoute } = require('../lib/errors');
const { authMiddleware, requireRole } = require('../lib/security');

const router = express.Router();
const calls = db.collection('calls');

async function addCallerDetails(call) {
  const caller = { name: call.callerName || call.callerEmail || 'Customer', email: call.callerEmail || null, phone: call.callerPhone || null };
  try {
    const user = await firebaseAuth.getUser(call.callerUid);
    caller.name = user.displayName || user.email || user.phoneNumber || caller.name;
    caller.email = user.email || caller.email;
    caller.phone = user.phoneNumber || caller.phone;
    caller.photoURL = user.photoURL || null;
  } catch { /* Backend-managed callers may not have a Firebase Auth profile. */ }
  return { ...call, caller };
}

module.exports = (io) => {
  router.post('/', authMiddleware, requireRole('customer'), asyncRoute(async (request, response) => {
    const mode = request.body?.mode;
    if (!['voice', 'video'].includes(mode)) throw httpError(400, 'Call mode must be voice or video.');
    const ref = calls.doc(crypto.randomUUID());
    const call = { mode, channel: `lumera-${crypto.randomUUID()}`, callerUid: request.user.uid, status: 'ringing', createdAt: FieldValue.serverTimestamp() };
    await ref.create(call);
    const result = { id: ref.id, ...call, createdAt: new Date().toISOString() };
    io.to('agents').emit('call:new', result);
    io.to('agents').emit('queue-updated');
    response.status(201).json({ call: result });
  }));

  router.get('/', authMiddleware, asyncRoute(async (request, response) => {
    const status = typeof request.query.status === 'string' ? request.query.status : '';
    const limit = Math.min(Math.max(Number(request.query.limit || 20), 1), 100);
    let query;
    if (request.user.role === 'customer') {
      query = calls.where('callerUid', '==', request.user.uid).orderBy('createdAt', 'desc');
      if (status) query = calls.where('callerUid', '==', request.user.uid).where('status', '==', status).orderBy('createdAt', 'desc');
    } else if (request.user.role === 'admin') {
      query = status ? calls.where('status', '==', status).orderBy('createdAt', 'desc') : calls.orderBy('createdAt', 'desc');
    } else if (status === 'ringing') {
      query = calls.where('status', '==', 'ringing').orderBy('createdAt', 'desc');
    } else {
      query = calls.where('agentUid', '==', request.user.uid).orderBy('createdAt', 'desc');
      if (status) query = calls.where('agentUid', '==', request.user.uid).where('status', '==', status).orderBy('createdAt', 'desc');
    }
    const snapshot = await query.limit(limit).get();
    response.json({ calls: snapshot.docs.map((item) => ({ id: item.id, ...item.data() })) });
  }));

  router.get('/:callId', authMiddleware, asyncRoute(async (request, response) => {
    const snapshot = await calls.doc(request.params.callId).get();
    if (!snapshot.exists) throw httpError(404, 'Call not found.');
    const call = snapshot.data();
    if (request.user.role === 'customer' && call.callerUid !== request.user.uid) throw httpError(403, 'You cannot access this call.');
    if (request.user.role === 'agent' && call.agentUid !== request.user.uid && !['ringing', 'missed', 'declined', 'ended'].includes(call.status)) throw httpError(403, 'You cannot access this call.');
    response.json({ call: await addCallerDetails({ id: snapshot.id, ...snapshot.data() }) });
  }));

  router.post('/:callId/accept', authMiddleware, requireRole('agent'), asyncRoute(async (request, response) => {
    const ref = calls.doc(request.params.callId);
    const value = await db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(ref);
      if (!snapshot.exists) throw httpError(404, 'Call not found.');
      if (snapshot.data().status !== 'ringing') throw httpError(409, 'This call is no longer waiting for an agent.');
      transaction.update(ref, { status: 'accepted', agentUid: request.user.uid, acceptedAt: FieldValue.serverTimestamp() });
      return { id: ref.id, ...snapshot.data(), status: 'accepted', agentUid: request.user.uid };
    });
    io.to(`call:${ref.id}`).emit('call:updated', value);
    io.to('agents').emit('call:updated', value);
    io.to('agents').emit('queue-updated');
    response.json({ call: value });
  }));

  for (const [action, nextStatus] of [['decline', 'declined'], ['end', 'ended']]) {
    router.post(`/:callId/${action}`, authMiddleware, asyncRoute(async (request, response) => {
      const ref = calls.doc(request.params.callId);
      const value = await db.runTransaction(async (transaction) => {
        const snapshot = await transaction.get(ref);
        if (!snapshot.exists) throw httpError(404, 'Call not found.');
        const call = snapshot.data();
        if (action === 'decline' && (request.user.role !== 'agent' || call.status !== 'ringing')) throw httpError(409, 'Only an agent can decline a ringing call.');
        const participant = request.user.role === 'customer'
          ? call.callerUid === request.user.uid
          : request.user.role === 'agent' && (action === 'decline' ? call.status === 'ringing' : call.agentUid === request.user.uid);
        if (!participant) throw httpError(403, 'You cannot update this call.');
        if (['ended', 'declined'].includes(call.status)) return { id: ref.id, ...call };
        const resolvedStatus = action === 'end' && call.status === 'ringing' ? 'missed' : nextStatus;
        transaction.update(ref, { status: resolvedStatus, ...(action === 'decline' ? { agentUid: request.user.uid } : {}), endedAt: FieldValue.serverTimestamp(), ...(resolvedStatus === 'missed' ? { missedAt: FieldValue.serverTimestamp() } : {}) });
        return { id: ref.id, ...call, status: resolvedStatus };
      });
      io.to(`call:${ref.id}`).emit('call:updated', value);
      io.to('agents').emit('call:updated', value);
      io.to('agents').emit('queue-updated');
      response.json({ call: value });
    }));
  }
  return router;
};
