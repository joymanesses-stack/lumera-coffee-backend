'use strict';

function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function asyncRoute(handler) {
  return (request, response, next) => Promise.resolve(handler(request, response, next)).catch(next);
}

function errorHandler(error, request, response, next) {
  if (response.headersSent) return next(error);
  const status = Number(error.status) || 500;
  if (status >= 500) console.error(`[${request.method} ${request.originalUrl}]`, error);
  const message = status >= 500 && process.env.NODE_ENV !== 'development'
    ? 'An unexpected server error occurred.'
    : error.message;
  response.status(status).json({ error: message });
}

module.exports = { httpError, asyncRoute, errorHandler };
