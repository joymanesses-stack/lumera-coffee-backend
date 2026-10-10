'use strict';

const express = require('express');
const { db, FieldValue, firebaseAuth } = require('../config');
const { asyncRoute, httpError } = require('../lib/errors');
const { authMiddleware, requireRole, users } = require('../lib/security');

const router = express.Router();
const auditLogs = db.collection('auditLogs');

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
