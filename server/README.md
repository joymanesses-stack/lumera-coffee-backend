# Lumera Backend

Backend-only REST and Socket.IO service for customer accounts, call center, persistent agent chat, inquiries, and administration. The frontend project was referenced for its current contracts; its files are not copied or changed here.

## Structure

- `src/config.js`: environment validation and Firebase Admin clients.
- `src/lib`: shared authentication, authorization, and HTTP error handling.
- `src/routes/auth.js`: backend accounts and Firebase token exchange.
- `src/routes/calls.js`: customer call history, agent queue actions, and call state.
- `src/routes/conversations.js`: persistent chat threads, assignment, messages, and history.
- `src/routes/dashboards.js`: role-specific customer, agent, and admin summaries.
- `src/routes/inquiries.js`: public quote submissions and staff inquiry management.
- `src/routes/admin.js`: user and agent management plus operational call/chat views.
- `src/realtime.js`: authenticated Socket.IO events and WebRTC signaling.
- `src/index.js`: app assembly and account bootstrap; root `index.js` starts it.

## Setup

1. Copy `.env.example` to `.env` and set `ALLOWED_ORIGINS`, a random `JWT_SECRET` with at least 32 characters, `FIREBASE_PROJECT_ID` (or `VITE_FIREBASE_PROJECT_ID`), and `FIRESTORE_DATABASE_ID` to the exact database ID shown in Firebase. The usual Firestore database ID is `(default)`.
2. Configure Firebase Admin credentials for that same Firebase project. For local Windows development, download a service-account JSON from Firebase Console → Project settings → Service accounts, store it privately (for example, `server/private/lumera-firebase-admin.json`), and set `GOOGLE_APPLICATION_CREDENTIALS=C:/full/path/to/server/private/lumera-firebase-admin.json` in the backend `.env`. Keep the JSON out of Git and never put it in the frontend. Alternatively, configure Google Application Default Credentials with the Google Cloud CLI. The backend uses Admin credentials to access Firestore and verify Firebase ID tokens.
3. The example config lists `sgahimbare20@gmail.com` in `ADMIN_EMAILS`. Firebase Email/Password or Google sign-in grants admin access only when Firebase marks that email verified. Change `ADMIN_EMAILS` to change the admin allowlist. `BOOTSTRAP_ADMIN_*` is optional and only creates a separate backend email/password admin account; leave both values empty when using Firebase. `BOOTSTRAP_AGENT_*` optionally creates a backend-managed agent account. Passwords are stored as scrypt hashes.
4. Run `npm install`, then `npm run dev` or `npm start` from this directory.

## Authentication and dashboards

- `POST /v1/auth/register` creates a backend-managed customer account with `{ "email", "password" }`.
- `POST /v1/auth/login` signs in backend-managed customer, agent, or admin accounts.
- `POST /v1/auth/firebase` exchanges a Firebase ID token with `{ "idToken" }`. This supports Firebase Email/Password and Google sign-in. Admin and agent access requires a trusted active membership record.
- All protected endpoints accept `Authorization: Bearer <token>`. The returned backend session is required for API calls and Socket.IO.
- `GET /v1/dashboard` selects the customer, agent, or admin summary by account role. Dedicated routes are `/v1/dashboard/user`, `/v1/dashboard/agent`, and `/v1/dashboard/admin`.

## Calls and customer chat

- `POST /v1/calls` (customer) with `{ "mode": "voice" | "video" }` opens a call request. A customer must sign in first.
- `GET /v1/calls?status=ringing&limit=20` lists the customer's history or agent queue.
- `POST /v1/calls/:callId/accept` and `/decline` (agent) update queue state. A participant ends a call with `POST /v1/calls/:callId/end`.
- `POST /v1/conversations` (customer) starts a persistent chat; `GET /v1/conversations` lists user history or the agent queue.
- Agents claim waiting chats with `POST /v1/conversations/:conversationId/accept`.
- Read history at `GET /v1/conversations/:conversationId/messages?limit=100&after=<messageId>` and send through `POST /v1/conversations/:conversationId/messages` with `{ "text" }`.
- `POST /v1/conversations/:conversationId/close` closes a thread. Its customer, assigned agent, or administrator can access it.

The Socket.IO server authenticates connections, broadcasts call and chat queue changes, persists chat messages before broadcasting, and restricts call signaling to the customer and assigned agent on accepted calls. Audio/video remains peer-to-peer; configure TURN for restrictive networks.

## Admin API

All routes below require an admin session:

- `GET /v1/admin/agents`, `POST /v1/admin/agents` with email/password, and `PATCH /v1/admin/agents/:agentId` with `{ "active": false }` manage agents.
- `GET /v1/admin/users` and `PATCH /v1/admin/users/:userId` manage customer accounts.
- `GET /v1/admin/calls` and `GET /v1/admin/conversations` provide operational views; `POST /v1/admin/calls/:callId/end` can end a call.
- The admin dashboard reports user, agent, call, chat, and inquiry counts plus recent call and chat activity.

For Firebase-backed staff, create `backendAdmins/{firebaseUid}` or `backendAgents/{firebaseUid}` through a trusted administrator process with `{ "active": true }`. The backend also recognizes the existing `agent/{uid}` and `agents/{uid}` memberships for compatibility. Never allow browser clients to write staff membership records.

The current website still needs its login card and dashboards connected to these APIs. This workspace contains the backend only.

After the frontend migration, update and deploy the website's Firestore rules so browsers cannot create or modify `calls`, `conversations`, their messages, or agent records directly. The backend uses Firebase Admin and is not restricted by client Firestore rules.
