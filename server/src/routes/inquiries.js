'use strict';

const express = require('express');
const { db, FieldValue } = require('../config');
const { httpError, asyncRoute } = require('../lib/errors');
const { authMiddleware, requireRole } = require('../lib/security');

const router = express.Router();
const inquiries = db.collection('inquiries');
const auditLogs = db.collection('auditLogs');

module.exports = (io) => {
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
    response.json({ inquiries: snapshot.docs.filter((doc) => !doc.data().deletedAt).map((doc) => ({ id: doc.id, ...doc.data() })) });
  }));

  const updateInquiry = asyncRoute(async (request, response) => {
    const status = request.body?.status;
    if (!['new', 'in_progress', 'contacted', 'closed'].includes(status)) throw httpError(400, 'Invalid inquiry status.');
    const ref = inquiries.doc(request.params.inquiryId);
    const snapshot = await ref.get();
    if (!snapshot.exists) throw httpError(404, 'Inquiry not found.');
    await ref.update({ status, updatedAt: FieldValue.serverTimestamp() });
    const result = { id: ref.id, ...snapshot.data(), status, updatedAt: new Date().toISOString() };
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
      await ref.update({ deletedAt: FieldValue.serverTimestamp(), deletedBy: request.user.uid, status: 'deleted' });
      await auditLogs.add({ action: 'inquiry.soft_delete', inquiryId: ref.id, actorUid: request.user.uid, createdAt: FieldValue.serverTimestamp() });
      io.to('agents').emit('queue-updated');
    }
    response.json({ deleted: true, id: ref.id });
  }));
  return router;
};
