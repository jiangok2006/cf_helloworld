# Hello World App

This project is a simple web application that displays "Hello World" using Cloudflare Pages for the UI and a Cloudflare Worker to handle requests.

## Project Structure

```
hello-world-app
├── public
│   └── index.html
├── worker
│   ├── index.js
│   └── wrangler.toml
├── package.json
└── README.md
```

## Setup Instructions

1. **Clone the repository**:
   ```
   git clone <repository-url>
   cd hello-world-app
   ```

2. **Install dependencies**:
   ```
   npm install
   ```

3. **Deploy the Cloudflare Worker**:
   Wrangler v3 replaced the old `publish` command with `deploy`. You can run Wrangler without installing it globally using `npx` or `npm exec`.
   From the project root run:
   ```bash
   cd worker
   npx wrangler deploy
   ```

   To run the worker locally during development:
   ```bash
   npx wrangler dev
   ```

   Optional: add a script to `package.json` and run via npm:
   ```json
   "scripts": {
     "deploy:worker": "wrangler deploy"
   }
   ```
   Then run:
   ```bash
   npm run deploy:worker --prefix .

4. **Database (D1) Migrations**

This project uses Cloudflare D1 migrations (single source for dev and prod).

- Configure the binding in `worker/wrangler.toml` (already set as `AUTH_DB`) and note `migrations_dir = "migrations"` under both environments.
- Apply migrations locally (development):

```bash
cd worker
npx wrangler d1 migrations apply AUTH_DB --env development --local
```

- Apply migrations to production:

```bash
cd worker
npx wrangler d1 migrations apply AUTH_DB --env production
```

The old `dev/schema.sql` and `prod/schema.sql` files have been removed; use migrations exclusively.

### Admin Bootstrap

An admin user is bootstrapped via migration `001_bootstrap_admin.sql`:
- Email: `jiangok2006@gmail.com`
- Role: `ADMIN`
- Active: `true`

Apply after the initial schema migration:

```bash
cd worker
npx wrangler d1 migrations apply AUTH_DB --env development --local   # development
npx wrangler d1 migrations apply AUTH_DB --env production            # production
```

## Passwordless (magic-link) authentication


This project includes a simple email link authentication flow backed by Cloudflare D1 and SendPulse.

Requirements:
- A Cloudflare D1 database (create via Cloudflare dashboard). Set the database name to `hello_auth` or update `worker/wrangler.toml` accordingly.
- A SendPulse application client (`client_id` and `client_secret`) — used to obtain an OAuth access token for sending transactional emails.

Setup steps:

1. Initialize D1 schema via migrations (tables: tokens, sessions, roles, users). See `worker/migrations/000_init.sql` and run the migration commands above.

2. Configure `worker/wrangler.toml` if needed: set `APP_URL` and `FROM_EMAIL` under `[vars]`.

3. Provide SendPulse credentials and secrets:

- Local: add the SendPulse credentials as Wrangler secrets:

```bash
npx wrangler secret put SENDPULSE_CLIENT_ID
npx wrangler secret put SENDPULSE_CLIENT_SECRET
```

- GitHub Actions: add repository secrets `SENDPULSE_CLIENT_ID` and `SENDPULSE_CLIENT_SECRET` (Settings → Secrets → Actions).

4. Request a magic link:

POST /auth/request with JSON body `{ "email": "you@example.com" }` — the worker stores a short-lived token and sends an email containing the sign-in link.

5. Verify the magic link:

`GET /auth/verify?token=...&email=...` — the worker validates the token, removes it, and responds with success while setting an HttpOnly session cookie. Use `/auth/session` without query params; the worker reads the session from `Cookie` (or `Authorization: Bearer`).

Security notes:
- Tokens expire after 15 minutes. Adjust `index.js` as needed.
- Use least-privilege credentials and rotate them regularly.

   ```

4. **Run the application**:
   You can open `public/index.html` in your browser to see the "Hello World" message.

## Usage

- The web application will display "Hello World" when accessed.
- The Cloudflare Worker will respond with "Hello World" to any incoming requests.

## License

This project is licensed under the MIT License.