# FairVote — People's Choice Award

A full-stack starter application with a PostgreSQL backend, student-roster matching, server-enforced voting limits, live results, and an admin panel.

## Voting rules enforced on the server
- Maximum of **3 total votes per eligible student ID**.
- Maximum of **1 vote per local calendar day** (default timezone: `Asia/Manila`).
- Database uniqueness constraint prevents duplicate same-day votes, including concurrent requests.
- Vote totals are calculated from database records, not browser state.
- Voting start/end are configured through environment variables.

## Important identity limitation
A student ID typed into a form is not proof that the person owns it. This starter checks IDs against an administrator-imported eligible roster, but a real public election should additionally verify identity using campus single sign-on, a one-time code to a verified campus email/phone, or in-person verification. Never publish a roster of student IDs or share admin credentials. Consider a privacy review before collecting student data.

## Requirements
- Node.js 20+
- PostgreSQL 14+

## Run locally
1. Create a PostgreSQL database named `fairvote`.
2. Copy `.env.example` to `.env`.
3. Set `DATABASE_URL`, a random `SESSION_SECRET` of at least 32 characters, voting start/end, and timezone.
4. Generate a bcrypt password hash for the administrator. For example, run `node -e "const b=require('bcryptjs'); b.hash(process.argv[1],12).then(console.log)" "YOUR-STRONG-ADMIN-PASSWORD"` and place the resulting hash in `ADMIN_PASSWORD_HASH`.
5. Install and start:
   ```bash
   npm install
   npm start
   ```
6. Open `http://localhost:3000/admin`, sign in, add candidates, then paste the eligible student IDs into the roster import area.

The server creates its database tables on first startup. Back up PostgreSQL before use.

## Deployment checklist
- Use a managed PostgreSQL service and private credentials.
- Set `NODE_ENV=production`; serve only over HTTPS.
- Set `DATABASE_URL`, `SESSION_SECRET`, `ADMIN_PASSWORD_HASH`, `VOTING_TIME_ZONE`, `VOTING_START`, and `VOTING_END` in the host's secret manager.
- Restrict administrator access where possible; rotate the admin password if it may have been exposed.
- Test with dummy IDs before launch and verify voting limits, voting dates, and candidate tally behavior.
- Establish a process for correcting eligibility errors and handling disputed votes.
- Do not use this starter for legally binding elections without an appropriate security and privacy review.

## Features
- Public voting page with live tally refresh.
- Admin login, candidate creation/activation, roster import, summary, and audit trail.
- Student IDs stored as HMAC hashes rather than plaintext.
- Session cookies are HttpOnly and SameSite=Strict; Secure is enabled in production.
- Rate limiting, Helmet security headers, parameterized SQL, and server-side enforcement.

## Current scope
This is source code ready for local setup and deployment. It is **not yet hosted publicly**. Configure an approved hosting provider before sharing a public voting URL.
