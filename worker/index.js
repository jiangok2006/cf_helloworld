export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === '/auth/request' && request.method === 'POST') {
        const { email } = await request.json();
        if (!email) return jsonResponse({ error: 'email required' }, 400);
        // Require that the user exists and is active before sending a magic link
        const ures = await env.AUTH_DB.prepare(
          `SELECT email, is_active FROM users WHERE email = ? LIMIT 1`
        ).bind(email).all();
        const row = ures && ures.results && ures.results[0];
        if (!row) return jsonResponse({ error: 'user not found' }, 404);
        if (!row.is_active) return jsonResponse({ error: 'user inactive' }, 403);
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
        // token valid — create session and remove token
        const sessionId = generateToken();
        const now = Date.now();
        const sessionExpires = now + 7 * 24 * 60 * 60 * 1000; // 7 days
        
        await env.AUTH_DB.prepare(
          `INSERT INTO sessions (session_id, email, created_at, expires_at) VALUES (?, ?, ?, ?)`
        ).bind(sessionId, email, now, sessionExpires).run();
        
        // Ensure user exists (default role USER); do not overwrite existing ADMIN
        await env.AUTH_DB.prepare(
          `INSERT OR IGNORE INTO users (email, role, is_active, created_at) VALUES (?, 'USER', 1, ?)`
        ).bind(email, now).run();

        await env.AUTH_DB.prepare(`DELETE FROM magic_tokens WHERE token = ?`).bind(token).run();

        // Set session as HttpOnly cookie; do not expose in body
        const cookie = `sessionId=${encodeURIComponent(sessionId)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 60 * 60}`;
        // Redirect to after-sign-in page while setting cookie
        return new Response(null, {
          status: 302,
          headers: {
            'Location': '/app.html',
            'Set-Cookie': cookie,
            'Referrer-Policy': 'no-referrer',
            'Cache-Control': 'no-store',
          },
        });
      }

      // Return current authenticated user (email + role)
      if (url.pathname === '/auth/me' && request.method === 'GET') {
        const sessionId = getSessionIdFromRequest(request);
        if (!sessionId) return jsonResponse({ error: 'sessionId required' }, 400);

        const res = await env.AUTH_DB.prepare(
          `SELECT session_id, email, expires_at FROM sessions WHERE session_id = ?`
        ).bind(sessionId).all();
        const session = res && res.results && res.results[0];
        if (!session) return jsonResponse({ error: 'invalid session' }, 401);
        if (Date.now() > session.expires_at) {
          await env.AUTH_DB.prepare(`DELETE FROM sessions WHERE session_id = ?`).bind(sessionId).run();
          return jsonResponse({ error: 'session expired' }, 401);
        }

        const ures = await env.AUTH_DB.prepare(
          `SELECT email, role, is_active FROM users WHERE email = ?`
        ).bind(session.email).all();
        const user = ures && ures.results && ures.results[0];
        if (!user) return jsonResponse({ ok: true, email: session.email, role: 'USER' });
        return jsonResponse({ ok: true, email: user.email, role: user.role });
      }

      if (url.pathname === '/auth/session' && request.method === 'GET') {
        const sessionId = getSessionIdFromRequest(request);
        if (!sessionId) return jsonResponse({ error: 'sessionId required' }, 400);
        
        const res = await env.AUTH_DB.prepare(
          `SELECT session_id, email, expires_at FROM sessions WHERE session_id = ?`
        ).bind(sessionId).all();
        
        const session = res && res.results && res.results[0];
        if (!session) return jsonResponse({ error: 'invalid session' }, 401);
        
        if (Date.now() > session.expires_at) {
          await env.AUTH_DB.prepare(`DELETE FROM sessions WHERE session_id = ?`).bind(sessionId).run();
          return jsonResponse({ error: 'session expired' }, 401);
        }
        
        return jsonResponse({ ok: true, email: session.email });
      }

      // Admin-only APIs: any path under /admin/* requires ADMIN role
      if (url.pathname.startsWith('/admin/')) {
        const sessionId = getSessionIdFromRequest(request);
        if (!sessionId) return jsonResponse({ error: 'unauthorized' }, 401);

        const sres = await env.AUTH_DB.prepare(
          `SELECT session_id, email, expires_at FROM sessions WHERE session_id = ?`
        ).bind(sessionId).all();
        const sess = sres && sres.results && sres.results[0];
        if (!sess) return jsonResponse({ error: 'unauthorized' }, 401);
        if (Date.now() > sess.expires_at) {
          await env.AUTH_DB.prepare(`DELETE FROM sessions WHERE session_id = ?`).bind(sessionId).run();
          return jsonResponse({ error: 'session expired' }, 401);
        }

        const ures = await env.AUTH_DB.prepare(
          `SELECT role FROM users WHERE email = ?`
        ).bind(sess.email).all();
        const user = ures && ures.results && ures.results[0];
        if (!user || user.role !== 'ADMIN') return jsonResponse({ error: 'forbidden' }, 403);

        // Authorized admin: return a generic OK for now
        return jsonResponse({ ok: true, path: url.pathname });
      }

      if (url.pathname === '/auth/signout' && request.method === 'POST') {
        const sessionId = getSessionIdFromRequest(request);
        if (sessionId) {
          await env.AUTH_DB.prepare(`DELETE FROM sessions WHERE session_id = ?`).bind(sessionId).run();
        }
        const clearCookie = 'sessionId=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0';
        return new Response(JSON.stringify({ ok: true }), {
          headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': clearCookie,
            'Cache-Control': 'no-store',
          },
        });
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

function getSessionIdFromRequest(request) {
  const auth = request.headers.get('Authorization');
  if (auth && auth.startsWith('Bearer ')) {
    return auth.slice(7).trim();
  }
  const cookieHeader = request.headers.get('Cookie') || '';
  const parts = cookieHeader.split(';').map(s => s.trim());
  const found = parts.find(s => s.startsWith('sessionId='));
  if (found) {
    const value = found.split('=')[1];
    return decodeURIComponent(value);
  }
  return null;
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
      from: { name: 'Hello World App', email: FROM_EMAIL },
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