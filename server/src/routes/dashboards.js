'use strict';

const express = require('express');
const { db, FieldValue, firebaseAuth } = require('../config');
const { asyncRoute } = require('../lib/errors');
const { authMiddleware, requireRole } = require('../lib/security');

const router = express.Router();
const calls = db.collection('calls');
const conversations = db.collection('conversations');
const inquiries = db.collection('inquiries');

const serialize = (id, value) => Object.fromEntries(Object.entries({ id, ...value }).map(([key, item]) => [key, item && typeof item.toDate === 'function' ? item.toDate().toISOString() : item]));
const items = (snapshot) => snapshot.docs.map((doc) => serialize(doc.id, doc.data()));

async function expireUnansweredCalls(snapshot) {
  const cutoff = Date.now() - 60_000;
  const expired = snapshot.docs.filter((doc) => {
    const createdAt = doc.data().createdAt;
    return createdAt && typeof createdAt.toDate === 'function' && createdAt.toDate().getTime() <= cutoff;
  });
  if (expired.length) {
    const batch = db.batch();
    expired.forEach((doc) => batch.update(doc.ref, { status: 'missed', missedAt: FieldValue.serverTimestamp() }));
    await batch.commit();
  }
  return new Set(expired.map((doc) => doc.id));
}

async function addCallerDetails(callsList) {
  return Promise.all(callsList.map(async (call) => {
    const caller = { name: call.callerName || 'Customer', email: call.callerEmail || null, phone: call.callerPhone || null };
    try {
      const user = await firebaseAuth.getUser(call.callerUid);
      caller.name = user.displayName || user.email || user.phoneNumber || caller.name;
      caller.email = user.email || caller.email;
      caller.phone = user.phoneNumber || caller.phone;
      caller.photoURL = user.photoURL || null;
    } catch { /* Backend-managed callers may not have a Firebase Auth profile. */ }
    if (!caller.email && call.callerUid) {
      const profile = await db.collection('backendUsers').doc(call.callerUid).get();
      if (profile.exists) {
        caller.email = profile.data().email || null;
        caller.name = profile.data().displayName || caller.email || caller.name;
      }
    }
    if (caller.name === 'Customer' && caller.email) caller.name = caller.email;
    return { ...call, caller };
  }));
}

router.get('/user', authMiddleware, requireRole('customer'), asyncRoute(async (request, response) => {
  const [callList, conversationList] = await Promise.all([
    calls.where('callerUid', '==', request.user.uid).orderBy('createdAt', 'desc').limit(20).get(),
    conversations.where('customerUid', '==', request.user.uid).orderBy('createdAt', 'desc').limit(20).get(),
  ]);
  response.json({ user: request.user, calls: items(callList), conversations: items(conversationList).filter((conversation) => !conversation.deletedAt) });
}));

const agentDashboard = asyncRoute(async (_request, response) => {
  const [recentCalls, waitingChats, activeChats, inquiryList] = await Promise.all([
    calls.orderBy('createdAt', 'desc').limit(200).get(),
    conversations.where('status', '==', 'waiting').orderBy('createdAt', 'desc').limit(30).get(),
    conversations.where('status', '==', 'active').where('agentUid', '==', _request.user.uid).orderBy('createdAt', 'desc').limit(30).get(),
    inquiries.orderBy('createdAt', 'desc').limit(30).get(),
  ]);
  const ringingCalls = { docs: recentCalls.docs.filter((doc) => doc.data().status === 'ringing') };
  const expiredIds = await expireUnansweredCalls(ringingCalls);
  const allCalls = items(recentCalls).map((call) => expiredIds.has(call.id) ? { ...call, status: 'missed', missedAt: new Date().toISOString() } : call);
  const callQueue = allCalls.filter((call) => call.status === 'ringing' && !expiredIds.has(call.id));
  const callHistory = await addCallerDetails(allCalls.filter((call) => ['missed', 'declined', 'ended'].includes(call.status)));
  const chats = [...items(waitingChats), ...items(activeChats)].sort((left, right) => (Date.parse(right.createdAt || '') || 0) - (Date.parse(left.createdAt || '') || 0)).slice(0, 30);
  response.json({ calls: callQueue, callHistory, conversations: chats.map((chat) => ({ ...chat, userUid: chat.customerUid, lastMessage: chat.lastMessagePreview || '' })), inquiries: items(inquiryList).filter((inquiry) => !inquiry.deletedAt) });
});
router.get('/agent', authMiddleware, requireRole('agent'), agentDashboard);
router.get('/dashboard', authMiddleware, requireRole('agent'), agentDashboard);

router.get('/admin', authMiddleware, requireRole('admin'), asyncRoute(async (_request, response) => {
  const [userCount, agentCount, callCount, ringingCount, conversationCount, waitingChatCount, inquiryCount, recentCalls, recentConversations] = await Promise.all([
    db.collection('backendUsers').count().get(), db.collection('backendAgents').count().get(),
    calls.count().get(), calls.where('status', '==', 'ringing').count().get(),
    conversations.count().get(), conversations.where('status', '==', 'waiting').count().get(),
    inquiries.count().get(), calls.orderBy('createdAt', 'desc').limit(10).get(),
    conversations.orderBy('createdAt', 'desc').limit(10).get(),
  ]);
  const [users, agents, admins, allCalls, allInquiries] = await Promise.all([
    db.collection('backendUsers').limit(200).get(),
    db.collection('backendAgents').limit(200).get(),
    db.collection('backendAdmins').limit(200).get(),
    calls.orderBy('createdAt', 'desc').limit(100).get(),
    inquiries.orderBy('createdAt', 'desc').limit(100).get(),
  ]);
  response.json({
    users: [...items(users), ...items(agents), ...items(admins)].map((user) => ({ ...user, uid: user.uid || user.id, displayName: user.displayName || user.email || '' })),
    calls: items(allCalls),
    inquiries: items(allInquiries),
    metrics: { users: userCount.data().count, agents: agentCount.data().count, calls: callCount.data().count, ringingCalls: ringingCount.data().count, conversations: conversationCount.data().count, waitingChats: waitingChatCount.data().count, inquiries: inquiryCount.data().count },
    recentCalls: items(recentCalls),
    recentConversations: items(recentConversations),
  });
}));

router.get('/', authMiddleware, asyncRoute(async (request, response) => {
  if (request.user.role === 'customer') {
    const [callList, conversationList] = await Promise.all([
      calls.where('callerUid', '==', request.user.uid).orderBy('createdAt', 'desc').limit(20).get(),
      conversations.where('customerUid', '==', request.user.uid).orderBy('createdAt', 'desc').limit(20).get(),
    ]);
    return response.json({ user: request.user, calls: items(callList), conversations: items(conversationList).filter((conversation) => !conversation.deletedAt) });
  }
  if (request.user.role === 'agent') {
    const [callQueue, waitingChats, activeChats, inquiryList] = await Promise.all([
      calls.where('status', '==', 'ringing').orderBy('createdAt', 'desc').limit(30).get(),
      conversations.where('status', '==', 'waiting').orderBy('createdAt', 'desc').limit(30).get(),
      conversations.where('status', '==', 'active').where('agentUid', '==', request.user.uid).orderBy('createdAt', 'desc').limit(30).get(),
      inquiries.orderBy('createdAt', 'desc').limit(30).get(),
    ]);
    const chats = [...items(waitingChats), ...items(activeChats)].sort((left, right) => (right.createdAt?.toMillis?.() || 0) - (left.createdAt?.toMillis?.() || 0)).slice(0, 30);
    return response.json({ calls: items(callQueue), conversations: chats, inquiries: items(inquiryList) });
  }
  const [userCount, agentCount, callCount, ringingCount, conversationCount, waitingChatCount, inquiryCount] = await Promise.all([
    db.collection('backendUsers').count().get(), db.collection('backendAgents').count().get(), calls.count().get(),
    calls.where('status', '==', 'ringing').count().get(), conversations.count().get(),
    conversations.where('status', '==', 'waiting').count().get(), inquiries.count().get(),
  ]);
  response.json({ metrics: { users: userCount.data().count, agents: agentCount.data().count, calls: callCount.data().count, ringingCalls: ringingCount.data().count, conversations: conversationCount.data().count, waitingChats: waitingChatCount.data().count, inquiries: inquiryCount.data().count } });
}));

module.exports = router;
