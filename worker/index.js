export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === '/auth/request' && request.method === 'POST') {
        const { email } = await request.json();
        if (!email) return jsonResponse({ error: 'email required' }, 400);
        const token = generateToken();
        const expiresAt = Date.now() + 15 * 60 * 1000; // 15 minutes
        // store token in D1
        await env.AUTH_DB.prepare(
          `INSERT INTO magic_tokens (token, email, expires_at) VALUES (?, ?, ?)`
        )
          .bind(token, email, expiresAt)
          .run();

        await sendMagicLink(email, token, env);
        return jsonResponse({ ok: true });
      }

      if (url.pathname === '/auth/verify' && request.method === 'GET') {
        const token = url.searchParams.get('token');
        const email = url.searchParams.get('email');
        if (!token || !email) return jsonResponse({ error: 'missing params' }, 400);
        const res = await env.AUTH_DB.prepare(
          `SELECT token, email, expires_at FROM magic_tokens WHERE token = ? AND email = ?`
        )
          .bind(token, email)
          .all();
        const row = res && res.results && res.results[0];
        if (!row) return jsonResponse({ error: 'invalid token' }, 400);
        if (Date.now() > row.expires_at) {
          // delete expired
          await env.AUTH_DB.prepare(`DELETE FROM magic_tokens WHERE token = ?`).bind(token).run();
          return jsonResponse({ error: 'token expired' }, 400);
        }
        // token valid — create session (omitted) and remove token
        await env.AUTH_DB.prepare(`DELETE FROM magic_tokens WHERE token = ?`).bind(token).run();
        return jsonResponse({ ok: true, email });
      }

      return new Response('Hello World from worker', {
        headers: { 'Content-Type': 'text/plain' },
      });
    } catch (err) {
      return jsonResponse({ error: String(err) }, 500);
    }
  }
};

function generateToken() {
  const arr = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sendMagicLink(email, token, env) {
  // Use SendPulse REST API (OAuth client credentials)
  const clientId = env.SENDPULSE_CLIENT_ID;
  const clientSecret = env.SENDPULSE_CLIENT_SECRET;
  const FROM_EMAIL = env.FROM_EMAIL || 'no-reply@example.com';
  const APP_URL = env.APP_URL || 'https://example.com';
  if (!clientId || !clientSecret) throw new Error('SENDPULSE_CLIENT_ID / SENDPULSE_CLIENT_SECRET not configured');

  // 1) get access token
  let accessToken;
  try {
    const tokenRes = await fetch('https://api.sendpulse.com/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret }),
    });
    const tokenJson = await tokenRes.json();
    accessToken = tokenJson && tokenJson.access_token;
    if (!accessToken) {
      console.error('No access token in response:', tokenJson);
      throw new Error('failed to obtain SendPulse access token');
    }
  } catch (err) {
    console.error('Error getting SendPulse token:', err.message || err);
    console.error('Full error:', JSON.stringify(err, Object.getOwnPropertyNames(err)));
    throw err;
  }

  const link = `${APP_URL.replace(/\/$/, '')}/auth/verify?token=${token}&email=${encodeURIComponent(email)}`;

  const payload = {
    email: {
      subject: 'Your sign-in link',
      from: { email: FROM_EMAIL },
      to: [{ email }],
      html: `<p>Click to sign in: <a href="${link}">${link}</a></p>`,
      text: `Sign in: ${link}`,
    },
  };

  const sendRes = await fetch('https://api.sendpulse.com/smtp/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  const responseText = await sendRes.text();
  if (!sendRes.ok) {
    throw new Error('SendPulse send failed: ' + responseText);
  }
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}