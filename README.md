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

## Passwordless (magic-link) authentication


This project includes a simple email link authentication flow backed by Cloudflare D1 and SendPulse.

Requirements:
- A Cloudflare D1 database (create via Cloudflare dashboard). Set the database name to `hello_auth` or update `worker/wrangler.toml` accordingly.
- A SendPulse application client (`client_id` and `client_secret`) — used to obtain an OAuth access token for sending transactional emails.

Setup steps:

1. Create the D1 table for tokens (run in D1 SQL runner):

```sql
CREATE TABLE IF NOT EXISTS magic_tokens (
   token TEXT PRIMARY KEY,
   email TEXT NOT NULL,
   expires_at INTEGER NOT NULL
);
```

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

GET /auth/verify?token=...&email=... — the worker validates the token, removes it, and responds with success. (You should extend this to create a session cookie or issue a JWT for your application.)

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