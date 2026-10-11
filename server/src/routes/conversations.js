'use strict';

const express = require('express');
const crypto = require('node:crypto');
const { db, FieldValue } = require('../config');
const { httpError, asyncRoute } = require('../lib/errors');
const { authMiddleware, requireRole } = require('../lib/security');

const conversations = db.collection('conversations');
const auditLogs = db.collection('auditLogs');
const deletedMessages = db.collection('deletedMessages');
const router = express.Router();

function canManageConversation(conversation, user) {
  return user.role === 'admin' || (user.role === 'agent' && (conversation.status === 'waiting' || conversation.agentUid === user.uid));
}

function canManageDeletedMessage(conversation, user, message) {
  return user.role === 'admin' || canManageConversation(conversation, user) || (user.role === 'agent' && message.deletedBy === user.uid);
}

function deletedMessageArchiveId(conversationId, messageId) {
  return crypto.createHash('sha256').update(`${conversationId}\0${messageId}`).digest('hex');
}

async function findDeletedMessageArchive(id) {
  // Older clients send the original message UUID, while newer clients may send
  // the archive document ID returned by GET /bin. Accept both forms.
  const byArchiveId = await deletedMessages.doc(id).get();
  if (byArchiveId.exists) return byArchiveId;
  const byMessageId = await deletedMessages.where('messageId', '==', id).limit(1).get();
  return byMessageId.empty ? null : byMessageId.docs[0];
}

function publicMessage(doc) {
  const value = doc.data();
  return { id: doc.id, ...value, text: value.deletedAt ? 'This message was deleted.' : value.text,
    ...(value.deletedAt?.toDate ? { deletedAt: value.deletedAt.toDate().toISOString() } : {}) };
}

function canReadConversation(conversation, user) {
  return user.role === 'admin' || (user.role === 'agent'
    ? conversation.agentUid === user.uid
    : conversation.customerUid === user.uid);
}

async function readConversation(id) {
  const snapshot = await conversations.doc(id).get();
  if (!snapshot.exists) throw httpError(404, 'Conversation not found.');
  return { ref: snapshot.ref, value: { id: snapshot.id, ...snapshot.data() } };
}

async function saveMessage(id, user, rawText, io) {
  const text = typeof rawText === 'string' ? rawText.trim() : '';
  if (!text || text.length > 4000) throw httpError(400, 'Message must contain 1 to 4000 characters.');
  const { ref, value } = await readConversation(id);
  if (!canReadConversation(value, user)) throw httpError(403, 'You cannot access this conversation.');
  if (value.status === 'closed' || value.deletedAt) throw httpError(409, 'This conversation is closed or deleted.');
  if (user.role === 'agent' && value.agentUid !== user.uid) throw httpError(403, 'Accept this conversation before replying.');
  const messageRef = ref.collection('messages').doc(crypto.randomUUID());
  const message = { id: messageRef.id, conversationId: id, senderUid: user.uid, senderRole: user.role, text, createdAt: new Date().toISOString() };
  await db.runTransaction(async (transaction) => {
    const current = await transaction.get(ref);
    if (!current.exists || current.data().status === 'closed' || current.data().deletedAt) throw httpError(409, 'This conversation is closed or deleted.');
    if (user.role === 'agent' && current.data().agentUid !== user.uid) throw httpError(403, 'Accept this conversation before replying.');
    transaction.create(messageRef, { ...message, createdAt: FieldValue.serverTimestamp() });
    transaction.update(ref, { lastMessageAt: FieldValue.serverTimestamp(), lastMessagePreview: text.slice(0, 180) });
  });
  io.to(`conversation:${id}`).emit('chat:message', message);
  io.to(`conversation:${id}`).emit('chat-message', message);
  io.to('agents').emit('conversation:updated', { ...value, lastMessageAt: message.createdAt, lastMessagePreview: text.slice(0, 180) });
  return message;
}

module.exports = (io) => {
  router.get('/', authMiddleware, asyncRoute(async (request, response) => {
    const limit = Math.min(Math.max(Number(request.query.limit || 30), 1), 100);
    if (request.user.role === 'customer') {
      const snapshot = await conversations.where('customerUid', '==', request.user.uid).orderBy('createdAt', 'desc').limit(limit).get();
      return response.json({ conversations: snapshot.docs.filter((item) => !item.data().deletedAt).map((item) => ({ id: item.id, ...item.data() })) });
    }
    const [waiting, assigned] = await Promise.all([
      conversations.where('status', '==', 'waiting').orderBy('createdAt', 'desc').limit(limit).get(),
      conversations.where('status', '==', 'active').where('agentUid', '==', request.user.uid).orderBy('createdAt', 'desc').limit(limit).get(),
    ]);
    const result = [...waiting.docs, ...assigned.docs].filter((item) => !item.data().deletedAt).map((item) => ({ id: item.id, ...item.data() }))
      .sort((left, right) => (right.createdAt?.toMillis?.() || 0) - (left.createdAt?.toMillis?.() || 0)).slice(0, limit);
    response.json({ conversations: result });
  }));

  router.post('/', authMiddleware, requireRole('customer'), asyncRoute(async (request, response) => {
    const ref = conversations.doc(crypto.randomUUID());
    const value = { customerUid: request.user.uid, customerEmail: request.user.email, status: 'waiting', createdAt: FieldValue.serverTimestamp(), lastMessageAt: FieldValue.serverTimestamp() };
    await ref.create(value);
    const conversation = { id: ref.id, ...value, createdAt: new Date().toISOString(), lastMessageAt: new Date().toISOString() };
    io.to('agents').emit('conversation:new', conversation);
    io.to('agents').emit('queue-updated');
    response.status(201).json({ conversation });
  }));

  router.post('/:conversationId/accept', authMiddleware, requireRole('agent'), asyncRoute(async (request, response) => {
    const ref = conversations.doc(request.params.conversationId);
    const conversation = await db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(ref);
      if (!snapshot.exists) throw httpError(404, 'Conversation not found.');
      if (snapshot.data().status !== 'waiting') throw httpError(409, 'This conversation is no longer waiting for an agent.');
      transaction.update(ref, { status: 'active', agentUid: request.user.uid, acceptedAt: FieldValue.serverTimestamp() });
      return { id: ref.id, ...snapshot.data(), status: 'active', agentUid: request.user.uid };
    });
    io.to(`conversation:${ref.id}`).emit('conversation:updated', conversation);
    io.to('agents').emit('conversation:updated', conversation);
    io.to('agents').emit('queue-updated');
    response.json({ conversation });
  }));

  router.get('/bin', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (request, response) => {
    const snapshot = await deletedMessages.orderBy('deletedAt', 'desc').limit(100).get();
    const messages = await Promise.all(snapshot.docs.map(async (doc) => {
      const data = doc.data();
      const conversation = await conversations.doc(data.conversationId).get();
      if (!conversation.exists || !canManageDeletedMessage(conversation.data(), request.user, data)) return null;
      const iso = (date) => date?.toDate ? date.toDate().toISOString() : null;
      return { id: doc.id, ...data, createdAt: iso(data.createdAt), deletedAt: iso(data.deletedAt) };
    }));
    response.json({ messages: messages.filter(Boolean) });
  }));

  router.post('/bin/messages/:messageId/restore', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (request, response) => {
    const archive = await findDeletedMessageArchive(request.params.messageId);
    if (!archive) throw httpError(404, 'Deleted message not found in Bin.');
    const archiveRef = archive.ref;
    const data = archive.data();
    const { ref: conversationRef, value } = await readConversation(data.conversationId);
    if (!canManageDeletedMessage(value, request.user, data)) throw httpError(403, 'You cannot manage this deleted message.');
    const messageRef = conversationRef.collection('messages').doc(data.messageId);
    const messageSnapshot = await messageRef.get();
    if (!messageSnapshot.exists) throw httpError(404, 'Original message not found.');
    await messageRef.update({ deletedAt: FieldValue.delete(), deletedBy: FieldValue.delete(), placeholderHidden: FieldValue.delete() });
    await archiveRef.delete();
    const latestVisible = await conversationRef.collection('messages').orderBy('createdAt', 'desc').limit(50).get();
    const previewMessage = latestVisible.docs.find((doc) => !doc.data().deletedAt);
    const lastMessagePreview = previewMessage?.data().text?.slice(0, 180) || '';
    await conversationRef.update({ lastMessagePreview, lastMessageAt: previewMessage?.data().createdAt || FieldValue.serverTimestamp() });
    io.to(`conversation:${data.conversationId}`).emit('conversation:message-preview-updated', { conversationId: data.conversationId, lastMessage: lastMessagePreview });
    await auditLogs.add({ action: 'conversation.message.restore', conversationId: data.conversationId, messageId: data.messageId, actorUid: request.user.uid, createdAt: FieldValue.serverTimestamp() });
    const restored = { id: data.messageId, ...messageSnapshot.data(), text: data.text, deletedAt: null, placeholderHidden: false };
    io.to(`conversation:${data.conversationId}`).emit('chat-message', restored);
    response.json({ restored: true, message: restored });
  }));

  router.delete('/bin/messages/:messageId', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (request, response) => {
    const archive = await findDeletedMessageArchive(request.params.messageId);
    if (!archive) throw httpError(404, 'Deleted message not found in Bin.');
    const archiveRef = archive.ref;
    const data = archive.data();
    const { ref: conversationRef, value } = await readConversation(data.conversationId);
    if (!canManageDeletedMessage(value, request.user, data)) throw httpError(403, 'You cannot manage this deleted message.');
    await conversationRef.collection('messages').doc(data.messageId).delete();
    await archiveRef.delete();
    io.to(`conversation:${data.conversationId}`).emit('chat-message-hidden', { id: data.messageId });
    await auditLogs.add({ action: 'conversation.message.permanent_delete', conversationId: data.conversationId, messageId: data.messageId, actorUid: request.user.uid, createdAt: FieldValue.serverTimestamp() });
    response.json({ deleted: true, id: data.messageId });
  }));

  router.get('/:conversationId/messages', authMiddleware, asyncRoute(async (request, response) => {
    const { ref, value } = await readConversation(request.params.conversationId);
    if (!canReadConversation(value, request.user)) throw httpError(403, 'You cannot access this conversation.');
    if (value.deletedAt) throw httpError(404, 'This conversation was deleted.');
    const limit = Math.min(Math.max(Number(request.query.limit || 100), 1), 200);
    let query = ref.collection('messages').orderBy('createdAt', 'asc');
    if (typeof request.query.after === 'string') {
      const cursor = await ref.collection('messages').doc(request.query.after).get();
      if (!cursor.exists) throw httpError(400, 'Message cursor was not found in this conversation.');
      query = query.startAfter(cursor);
    }
    const snapshot = await query.limit(limit).get();
    response.json({ messages: snapshot.docs.filter((doc) => request.user.role !== 'customer' || !doc.data().deletedAt).filter((doc) => request.user.role === 'customer' || !doc.data().placeholderHidden).map(publicMessage), nextCursor: snapshot.docs.length === limit ? snapshot.docs[snapshot.docs.length - 1].id : null });
  }));

  router.delete('/:conversationId/messages/:messageId', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (request, response) => {
    const { ref: conversationRef, value } = await readConversation(request.params.conversationId);
    if (!canManageConversation(value, request.user)) throw httpError(403, 'You cannot manage this conversation.');
    const messageRef = conversationRef.collection('messages').doc(request.params.messageId);
    const messageSnapshot = await messageRef.get();
    if (!messageSnapshot.exists) throw httpError(404, 'Message not found.');
    if (messageSnapshot.data().deletedAt) return response.json({ deleted: true, id: messageRef.id });
    const original = messageSnapshot.data();
    await deletedMessages.doc(deletedMessageArchiveId(conversationRef.id, messageRef.id)).set({
      messageId: messageRef.id, conversationId: conversationRef.id, customerUid: value.customerUid || null,
      customerEmail: value.customerEmail || null, senderUid: original.senderUid || null, senderRole: original.senderRole || 'customer',
      text: original.text || '', createdAt: original.createdAt || null, deletedAt: FieldValue.serverTimestamp(), deletedBy: request.user.uid,
    });
    await messageRef.update({ text: '[Message deleted]', deletedAt: FieldValue.serverTimestamp(), deletedBy: request.user.uid, placeholderHidden: false });
    const latestVisible = await conversationRef.collection('messages').orderBy('createdAt', 'desc').limit(50).get();
    const previewMessage = latestVisible.docs.find((doc) => !doc.data().deletedAt);
    const lastMessagePreview = previewMessage?.data().text?.slice(0, 180) || '';
    await conversationRef.update({ lastMessagePreview, lastMessageAt: previewMessage?.data().createdAt || FieldValue.serverTimestamp() });
    io.to(`conversation:${conversationRef.id}`).emit('conversation:message-preview-updated', { conversationId: conversationRef.id, lastMessage: lastMessagePreview });
    await auditLogs.add({ action: 'conversation.message.soft_delete', conversationId: conversationRef.id, messageId: messageRef.id, actorUid: request.user.uid, createdAt: FieldValue.serverTimestamp() });
    const message = { id: messageRef.id, ...original, text: 'This message was deleted.', deletedAt: new Date().toISOString(), placeholderHidden: false };
    io.to(`conversation:${conversationRef.id}`).emit('chat-message-deleted', { id: message.id });
    io.to(`conversation:${conversationRef.id}`).emit('chat:message', message);
    io.to(`conversation:${conversationRef.id}`).emit('chat-message', message);
    response.json({ deleted: true, message });
  }));

  router.delete('/:conversationId/messages/:messageId/placeholder', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (request, response) => {
    const { ref: conversationRef, value } = await readConversation(request.params.conversationId);
    if (!canManageConversation(value, request.user)) throw httpError(403, 'You cannot manage this conversation.');
    const messageRef = conversationRef.collection('messages').doc(request.params.messageId);
    const messageSnapshot = await messageRef.get();
    if (!messageSnapshot.exists || !messageSnapshot.data().deletedAt) throw httpError(404, 'Deleted message marker not found.');
    if (!messageSnapshot.data().placeholderHidden) {
      await messageRef.update({ placeholderHidden: true, placeholderHiddenAt: FieldValue.serverTimestamp(), placeholderHiddenBy: request.user.uid });
      await auditLogs.add({ action: 'conversation.message.hide_placeholder', conversationId: conversationRef.id, messageId: messageRef.id, actorUid: request.user.uid, createdAt: FieldValue.serverTimestamp() });
    }
    io.to(`conversation:${conversationRef.id}`).emit('chat-message-hidden', { id: messageRef.id });
    response.json({ hidden: true, id: messageRef.id });
  }));

  router.delete('/:conversationId', authMiddleware, requireRole('agent', 'admin'), asyncRoute(async (request, response) => {
    const { ref, value } = await readConversation(request.params.conversationId);
    if (!canManageConversation(value, request.user)) throw httpError(403, 'You cannot manage this conversation.');
    if (!value.deletedAt) {
      await ref.update({ status: 'deleted', deletedPreviousStatus: value.status, deletedAt: FieldValue.serverTimestamp(), deletedBy: request.user.uid });
      await auditLogs.add({ action: 'conversation.soft_delete', conversationId: ref.id, customerUid: value.customerUid, actorUid: request.user.uid, createdAt: FieldValue.serverTimestamp() });
    }
    const deleted = { ...value, status: 'deleted', deletedAt: new Date().toISOString() };
    io.to(`conversation:${ref.id}`).emit('conversation:updated', deleted);
    io.to('agents').emit('queue-updated');
    response.json({ deleted: true, conversation: deleted });
  }));

  router.post('/:conversationId/messages', authMiddleware, requireRole('customer', 'agent'), asyncRoute(async (request, response) => {
    const message = await saveMessage(request.params.conversationId, request.user, request.body?.text, io);
    response.status(201).json({ message });
  }));

  router.post('/:conversationId/close', authMiddleware, asyncRoute(async (request, response) => {
    const { ref, value } = await readConversation(request.params.conversationId);
    if (!canReadConversation(value, request.user)) throw httpError(403, 'You cannot close this conversation.');
    if (value.status !== 'closed') await ref.update({ status: 'closed', closedAt: FieldValue.serverTimestamp() });
    const conversation = { ...value, status: 'closed' };
    io.to(`conversation:${ref.id}`).emit('conversation:updated', conversation);
    io.to('agents').emit('conversation:updated', conversation);
    response.json({ conversation });
  }));
  return router;
};

module.exports.saveMessage = saveMessage;
