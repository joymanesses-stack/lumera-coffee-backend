'use strict';

const crypto = require('node:crypto');
const http = require('node:http');
const express = require('express');
const { Server } = require('socket.io');
const { config, db, FieldValue } = require('./config');
const { emailId, normalizeEmail, validPassword, hashPassword } = require('./lib/security');
const { errorHandler } = require('./lib/errors');
const { attachRealtime } = require('./realtime');
const authRoutes = require('./routes/auth');
const callRoutes = require('./routes/calls');
const conversationRoutes = require('./routes/conversations');
const inquiryRoutes = require('./routes/inquiries');
const dashboardRoutes = require('./routes/dashboards');
const adminRoutes = require('./routes/admin');
const agentRoutes = require('./routes/agent');

function createApp() {
  const app = express();
  const httpServer = http.createServer(app);
  const io = new Server(httpServer, {
    cors: { origin: config.origins, methods: ['GET', 'POST', 'PATCH', 'DELETE'] },
    allowRequest: (request, callback) => callback(null, config.origins.includes(request.headers.origin)),
    maxHttpBufferSize: 1e6,
    transports: ['websocket', 'polling'],
  });

  app.disable('x-powered-by');
  app.use(express.json({ limit: '32kb' }));
  app.use((request, response, next) => {
    response.setHeader('Access-Control-Allow-Origin', config.origins.includes(request.headers.origin) ? request.headers.origin : 'null');
    response.setHeader('Vary', 'Origin');
    response.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    response.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
    if (request.method === 'OPTIONS') return response.sendStatus(204);
    next();
  });

  app.get('/health', (_request, response) => response.json({ status: 'ok' }));
  app.get('/v1/health', (_request, response) => response.json({ status: 'ok' }));
  app.use('/v1/auth', authRoutes);
  app.use('/v1/calls', callRoutes(io));
  app.use('/v1/conversations', conversationRoutes(io));
  app.use('/v1/inquiries', inquiryRoutes(io));
  app.use('/v1/dashboard', dashboardRoutes);
  app.use('/v1/agent', agentRoutes);
  app.use('/v1/agent', dashboardRoutes);
  app.use('/v1/admin', adminRoutes(io));
  attachRealtime(io);
  app.use(errorHandler);
  return { app, httpServer, io };
}

async function bootstrapAccount(collectionName, envPrefix, role) {
  const email = normalizeEmail(process.env[`${envPrefix}_EMAIL`]);
  const password = process.env[`${envPrefix}_PASSWORD`];
  if (!email && !password) return;
  if (!email || !validPassword(password)) throw new Error(`Set both ${envPrefix}_EMAIL and a ${envPrefix}_PASSWORD of at least 10 characters.`);
  const id = `local_${emailId(email)}`;
  const ref = db.collection(collectionName).doc(id);
  const snapshot = await ref.get();
  if (snapshot.exists) return;
  await ref.create({ uid: id, email, role, active: true, password: hashPassword(password), createdAt: FieldValue.serverTimestamp() });
  console.log(`Bootstrapped ${role} account for ${email}`);
}

async function start() {
  await bootstrapAccount('backendAgents', 'BOOTSTRAP_AGENT', 'agent');
  await bootstrapAccount('backendAdmins', 'BOOTSTRAP_ADMIN', 'admin');
  const { httpServer } = createApp();
  httpServer.listen(config.port, '0.0.0.0', () => console.log(`Lumera backend listening on port ${config.port}`));
}

if (require.main === module) {
  start().catch((error) => {
    console.error(`Backend startup failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { createApp, start };
