'use strict';

const express = require('express');
const { db, FieldValue } = require('../config');
const { httpError, asyncRoute } = require('../lib/errors');
const { authMiddleware, requireRole } = require('../lib/security');

const router = express.Router();
const inquiries = db.collection('inquiries');
const auditLogs = db.collection('auditLogs');

module.exports = (io) => {
  router.get('/bin', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (_request, response) => {
    const snapshot = await inquiries.where('deletedAt', '!=', null).orderBy('deletedAt', 'desc').limit(100).get();
    response.json({ inquiries: snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() })) });
  }));

  router.post('/bin/:inquiryId/restore', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (request, response) => {
    const ref = inquiries.doc(request.params.inquiryId);
    const snapshot = await ref.get();
    if (!snapshot.exists || !snapshot.data().deletedAt) throw httpError(404, 'Deleted inquiry not found in Bin.');
    const inquiry = snapshot.data();
    const status = inquiry.deletedPreviousStatus || 'new';
    await ref.update({
      deletedAt: FieldValue.delete(), deletedBy: FieldValue.delete(), deletedPreviousStatus: FieldValue.delete(),
      status, restoredAt: FieldValue.serverTimestamp(), restoredBy: request.user.uid,
    });
    await auditLogs.add({ action: 'inquiry.restore', inquiryId: ref.id, actorUid: request.user.uid, createdAt: FieldValue.serverTimestamp() });
    const { deletedAt, deletedBy, deletedPreviousStatus, ...restoredFields } = inquiry;
    const restored = { id: ref.id, ...restoredFields, status, deletedAt: null };
    io.to('agents').emit('inquiry:updated', restored);
    io.to('agents').emit('queue-updated');
    response.json({ restored: true, inquiry: restored });
  }));

  router.delete('/bin/:inquiryId', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (request, response) => {
    const ref = inquiries.doc(request.params.inquiryId);
    const snapshot = await ref.get();
    if (!snapshot.exists || !snapshot.data().deletedAt) throw httpError(404, 'Deleted inquiry not found in Bin.');
    await ref.delete();
    await auditLogs.add({ action: 'inquiry.permanent_delete', inquiryId: ref.id, actorUid: request.user.uid, createdAt: FieldValue.serverTimestamp() });
    io.to('agents').emit('queue-updated');
    response.json({ deleted: true, id: ref.id });
  }));

  router.post('/', asyncRoute(async (request, response) => {
    const data = request.body || {};
    const contactName = typeof data.contactName === 'string' ? data.contactName.trim() : '';
    const email = typeof data.email === 'string' ? data.email.trim().toLowerCase() : '';
    const message = typeof data.message === 'string' ? data.message.trim() : '';
    if (!contactName || contactName.length > 160 || !/^\S+@\S+\.\S+$/.test(email) || !message || message.length > 4000) throw httpError(400, 'A contact name, valid email, and message of 4000 characters or less are required.');
    const inquiry = { contactName, email, message, status: 'new', createdAt: FieldValue.serverTimestamp() };
    for (const key of ['companyName', 'phone', 'coffeeType', 'quantityRequired']) if (typeof data[key] === 'string') inquiry[key] = data[key].trim().slice(0, 300);
    const ref = await inquiries.add(inquiry);
    const result = { id: ref.id, ...inquiry, createdAt: new Date().toISOString() };
    io.to('agents').emit('inquiry:new', result);
    io.to('agents').emit('queue-updated');
    response.status(201).json({ id: ref.id, inquiry: result });
  }));

  router.get('/', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (request, response) => {
    const limit = Math.min(Math.max(Number(request.query.limit || 50), 1), 100);
    const snapshot = await inquiries.orderBy('createdAt', 'desc').limit(limit).get();
    const result = snapshot.docs.filter((doc) => !doc.data().deletedAt).map((doc) => ({ id: doc.id, ...doc.data() }))
      .filter((inquiry) => request.user.role !== 'agent' || !inquiry.assignedAgentUid || inquiry.assignedAgentUid === request.user.uid);
    response.json({ inquiries: result });
  }));

  const updateInquiry = asyncRoute(async (request, response) => {
    const status = request.body?.status;
    if (!['new', 'in_progress', 'contacted', 'closed'].includes(status)) throw httpError(400, 'Invalid inquiry status.');
    if (Object.prototype.hasOwnProperty.call(request.body || {}, 'assignedAgentUid') && request.user.role !== 'admin') {
      throw httpError(403, 'Only an administrator can assign an inquiry.');
    }
    const ref = inquiries.doc(request.params.inquiryId);
    const snapshot = await ref.get();
    if (!snapshot.exists) throw httpError(404, 'Inquiry not found.');
    if (snapshot.data().deletedAt) throw httpError(409, 'Restore this inquiry from Bin before updating it.');
    const update = { status, updatedAt: FieldValue.serverTimestamp() };
    let assignedAgentUid = snapshot.data().assignedAgentUid || null;
    if (Object.prototype.hasOwnProperty.call(request.body || {}, 'assignedAgentUid')) {
      assignedAgentUid = typeof request.body.assignedAgentUid === 'string' && request.body.assignedAgentUid.trim()
        ? request.body.assignedAgentUid.trim() : null;
      if (assignedAgentUid) {
        const agent = await db.collection('backendAgents').doc(assignedAgentUid).get();
        if (!agent.exists || agent.data().active !== true) throw httpError(400, 'Choose an active agent.');
      }
      update.assignedAgentUid = assignedAgentUid || FieldValue.delete();
    }
    await ref.update(update);
    const result = { id: ref.id, ...snapshot.data(), status, assignedAgentUid, updatedAt: new Date().toISOString() };
    io.to('agents').emit('inquiry:updated', result);
    io.to('agents').emit('queue-updated');
    response.json({ inquiry: result });
  });
  router.patch('/:inquiryId', authMiddleware, requireRole('agent', 'admin'), updateInquiry);
  router.patch('/agent/:inquiryId', authMiddleware, requireRole('agent', 'admin'), updateInquiry);

  router.delete('/:inquiryId', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (request, response) => {
    const ref = inquiries.doc(request.params.inquiryId);
    const snapshot = await ref.get();
    if (!snapshot.exists) throw httpError(404, 'Inquiry not found.');
    if (!snapshot.data().deletedAt) {
      await ref.update({ deletedAt: FieldValue.serverTimestamp(), deletedBy: request.user.uid, deletedPreviousStatus: snapshot.data().status || 'new', status: 'deleted' });
      await auditLogs.add({ action: 'inquiry.soft_delete', inquiryId: ref.id, actorUid: request.user.uid, createdAt: FieldValue.serverTimestamp() });
      io.to('agents').emit('queue-updated');
    }
    response.json({ deleted: true, id: ref.id });
  }));
  return router;
};
