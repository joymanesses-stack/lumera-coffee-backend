'use strict';

const crypto = require('node:crypto');
const { db, FieldValue, config } = require('./config');
const { authenticateToken } = require('./lib/security');
const { saveMessage } = require('./routes/conversations');

function iceServersFor(uid) {
  const servers = [{ urls: config.stunUrls }];
  const secret = process.env.TURN_SHARED_SECRET;
  if (config.turnUrls.length && secret) {
    const username = `${Math.floor(Date.now() / 1000) + 3600}:${uid}`;
    servers.push({ urls: config.turnUrls, username, credential: crypto.createHmac('sha1', secret).update(username).digest('base64') });
  }
  return servers;
}

function canReadConversation(conversation, user) {
  if (user.role === 'admin') return true;
  return user.role === 'agent' ? conversation.agentUid === user.uid : conversation.customerUid === user.uid;
}

function attachRealtime(io) {
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth?.token;
      if (typeof token !== 'string') throw new Error('A backend or Firebase session is required.');
      socket.data.user = await authenticateToken(token);
      next();
    } catch (error) { next(new Error(error.message || 'Authentication failed.')); }
  });

  io.on('connection', (socket) => {
    if (['agent', 'admin'].includes(socket.data.user.role)) socket.join('agents');

    socket.on('join-call', async (payload = {}) => {
      try {
        const callId = payload.callId;
        if (typeof callId !== 'string' || callId.length > 128) throw new Error('Invalid call ID.');
        const snapshot = await db.collection('calls').doc(callId).get();
        if (!snapshot.exists) throw new Error('Call not found.');
        const call = snapshot.data();
        const user = socket.data.user;
        const role = user.role === 'agent' && call.agentUid === user.uid ? 'agent' : user.role === 'customer' && call.callerUid === user.uid ? 'caller' : null;
        if (!role) throw new Error('You are not a participant in this call.');
        if (call.status !== 'accepted') throw new Error('The call must be accepted before connecting.');
        const room = `call:${callId}`;
        const peers = await io.in(room).fetchSockets();
        const joined = socket.rooms.has(room);
        if (peers.some((peer) => peer.data.role === role && peer.data.user.uid !== user.uid)) throw new Error('The participant slot is already in use.');
        if (peers.length >= 2 && !joined) throw new Error('This call already has two participants.');
        socket.data.callId = callId;
        socket.data.role = role;
        await socket.join(room);
        socket.emit('ice-server-config', iceServersFor(user.uid));
        socket.emit('room-ready', { peerCount: peers.length + (joined ? 0 : 1) });
        socket.to(room).emit('peer-joined', { role });
      } catch (error) { socket.emit('call-error', { message: error.message || 'Could not join this call.' }); }
    });

    socket.on('join-conversation', async (payload = {}) => {
      try {
        const id = payload.conversationId;
        if (typeof id !== 'string' || id.length > 128) throw new Error('Invalid conversation ID.');
        const snapshot = await db.collection('conversations').doc(id).get();
        if (!snapshot.exists) throw new Error('Conversation not found.');
        const conversation = snapshot.data();
        if (conversation.deletedAt) throw new Error('This conversation was deleted.');
        if (!canReadConversation(conversation, socket.data.user)) throw new Error('You cannot join this conversation.');
        if (socket.data.user.role === 'agent' && conversation.status !== 'active') throw new Error('Accept this conversation before joining.');
        await socket.join(`conversation:${id}`);
        socket.emit('conversation:ready', { conversationId: id });
        socket.emit('conversation-ready', { conversationId: id });
      } catch (error) { socket.emit('chat:error', { message: error.message || 'Could not join this conversation.' }); socket.emit('chat-error', { message: error.message || 'Could not join this conversation.' }); }
    });

    socket.on('send-message', async (payload = {}) => {
      try {
        const id = payload.conversationId;
        if (typeof id !== 'string' || !socket.rooms.has(`conversation:${id}`)) throw new Error('Join the conversation before sending a message.');
        const message = await saveMessage(id, socket.data.user, payload.text, io);
        socket.emit('chat:sent', { messageId: message.id });
      } catch (error) { socket.emit('chat:error', { message: error.message || 'Could not send this message.' }); socket.emit('chat-error', { message: error.message || 'Could not send this message.' }); }
    });

    for (const eventName of ['offer', 'answer', 'ice-candidate']) {
      socket.on(eventName, (payload = {}) => {
        const id = socket.data.callId;
        if (!id || !socket.rooms.has(`call:${id}`)) return;
        const value = eventName === 'ice-candidate' ? payload.candidate : payload.description;
        if (value && typeof value === 'object') socket.to(`call:${id}`).emit(eventName, payload);
      });
    }

    socket.on('disconnecting', () => {
      if (socket.data.callId) socket.to(`call:${socket.data.callId}`).emit('peer-left');
    });
  });
}

module.exports = { attachRealtime };
