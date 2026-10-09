# SY Chat Web — Secure TypeScript Edition

This is a secure starting architecture for SY Chat Web. TypeScript is used for the browser client and the Node.js server; PostgreSQL is the SQL database.

## Security included

- Argon2id password hashing (OWASP-recommended modern password hashing).
- Server-side sessions stored in PostgreSQL, with HttpOnly + SameSite cookies.
- CSRF token checks on state-changing HTTP requests.
- Helmet security headers and a restrictive Content Security Policy.
- Rate limiting on login/registration and room messaging endpoints.
- Parameterized PostgreSQL queries to prevent SQL injection.
- Server-side validation with Zod.
- No passwords or database credentials in browser storage.
- WebSocket connections are authenticated using the server session.

## Setup

1. Install Node.js and PostgreSQL.
2. Create a PostgreSQL database/user, then copy `.env.example` to `.env` and fill it in.
3. Run `psql "$DATABASE_URL" -f schema.sql`.
4. Run `npm install`.
5. Run `npm run build`.
6. Run `npm start`.
7. Open `http://localhost:3000`.

For production, deploy behind HTTPS, use a strong random SESSION_SECRET, restrict the database role, and put uploaded media behind an authenticated object-storage layer rather than storing files in localStorage.

This is a secure MVP foundation, not a claim that a production chat service is impossible to compromise. Production systems still need dependency updates, TLS, backups, monitoring, abuse controls, privacy controls, secure media storage, and security testing.
