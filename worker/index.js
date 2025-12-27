export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === '/auth/request' && request.method === 'POST') {
        const body = await request.json();
        const email = body && body.email;
        const remember = !!(body && body.remember);
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

        await sendMagicLink(email, token, env, remember);
        return jsonResponse({ ok: true });
      }

      if (url.pathname === '/auth/verify' && request.method === 'GET') {
        const token = url.searchParams.get('token');
        const email = url.searchParams.get('email');
        const remember = url.searchParams.get('remember') === '1';
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
        const sessionExpires = now + 1 * 24 * 60 * 60 * 1000; // 1 day
        
        await env.AUTH_DB.prepare(
          `INSERT INTO sessions (session_id, email, created_at, expires_at) VALUES (?, ?, ?, ?)`
        ).bind(sessionId, email, now, sessionExpires).run();
        
        // Ensure user exists (default role USER); do not overwrite existing ADMIN
        await env.AUTH_DB.prepare(
          `INSERT OR IGNORE INTO users (email, role, is_active, created_at) VALUES (?, 'USER', 1, ?)`
        ).bind(email, now).run();

        await env.AUTH_DB.prepare(`DELETE FROM magic_tokens WHERE token = ?`).bind(token).run();

        // Set session as HttpOnly cookie; do not expose in body
        const sessionCookie = `sessionId=${encodeURIComponent(sessionId)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${1 * 24 * 60 * 60}`;
        const headers = new Headers({
          'Location': '/app.html',
          'Set-Cookie': sessionCookie,
          'Referrer-Policy': 'no-referrer',
          'Cache-Control': 'no-store',
        });
        if (remember) {
          const rememberToken = generateToken();
          const tokenHash = await sha256Hex(rememberToken);
          const rNow = Date.now();
          const rExp = rNow + 90 * 24 * 60 * 60 * 1000; // 90 days
          const ua = request.headers.get('User-Agent') || '';
          const uaHash = await sha256Hex(ua);
          await env.AUTH_DB.prepare(
            `INSERT OR REPLACE INTO remember_tokens (token_hash, email, created_at, expires_at, ua_hash) VALUES (?, ?, ?, ?, ?)`
          ).bind(tokenHash, email, rNow, rExp, uaHash).run();
          const rememberCookie = `remember=${encodeURIComponent(rememberToken)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${90 * 24 * 60 * 60}`;
          headers.append('Set-Cookie', rememberCookie);
        }
        // Redirect to after-sign-in page while setting cookies
        return new Response(null, { status: 302, headers });
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

      // Admin: list all users (email, role, is_active, created_at)
      if (url.pathname === '/admin/users' && request.method === 'GET') {
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

        const listRes = await env.AUTH_DB.prepare(
          `SELECT email, role, is_active, created_at FROM users ORDER BY email`
        ).all();
        const users = (listRes.results || []).map(r => ({ email: r.email, role: r.role, is_active: r.is_active, created_at: r.created_at }));
        return jsonResponse({ ok: true, users });
      }

      // Admin: add user
      if (url.pathname === '/admin/users' && request.method === 'POST') {
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
        const admin = ures && ures.results && ures.results[0];
        if (!admin || admin.role !== 'ADMIN') return jsonResponse({ error: 'forbidden' }, 403);

        const body = await request.json().catch(() => ({}));
        const email = body && String(body.email || '').trim().toLowerCase();
        let role = (body && String(body.role || 'USER').toUpperCase()) || 'USER';
        if (!email) return jsonResponse({ error: 'email required' }, 400);
        if (!/^.+@.+\..+$/.test(email)) return jsonResponse({ error: 'invalid email' }, 400);
        if (!['USER','ADMIN'].includes(role)) role = 'USER';
        const now = Date.now();
        const exist = await env.AUTH_DB.prepare(`SELECT email FROM users WHERE email = ?`).bind(email).all();
        if (exist.results && exist.results[0]) return jsonResponse({ error: 'user exists' }, 409);
        await env.AUTH_DB.prepare(
          `INSERT INTO users (email, role, is_active, created_at) VALUES (?, ?, 1, ?)`
        ).bind(email, role, now).run();
        return jsonResponse({ ok: true });
      }

      // Admin: delete user
      if (url.pathname === '/admin/users' && request.method === 'DELETE') {
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
        const admin = ures && ures.results && ures.results[0];
        if (!admin || admin.role !== 'ADMIN') return jsonResponse({ error: 'forbidden' }, 403);
        const targetEmail = url.searchParams.get('email');
        if (!targetEmail) return jsonResponse({ error: 'email required' }, 400);
        if (targetEmail.toLowerCase() === sess.email.toLowerCase()) return jsonResponse({ error: 'cannot delete self' }, 400);
        // Prevent deleting the last active admin
        const target = await env.AUTH_DB.prepare(`SELECT role, is_active FROM users WHERE email = ?`).bind(targetEmail).all();
        const t = target.results && target.results[0];
        if (t && t.role === 'ADMIN' && t.is_active) {
          const cntRes = await env.AUTH_DB.prepare(`SELECT COUNT(*) AS c FROM users WHERE role = 'ADMIN' AND is_active = 1 AND email != ?`).bind(targetEmail).all();
          const c = cntRes.results && cntRes.results[0] && cntRes.results[0].c;
          if (!c) return jsonResponse({ error: 'cannot delete last active admin' }, 400);
        }
        await env.AUTH_DB.prepare(`DELETE FROM users WHERE email = ?`).bind(targetEmail).run();
        return jsonResponse({ ok: true });
      }

      // Admin: toggle user active
      if (url.pathname === '/admin/users/toggle' && request.method === 'POST') {
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
        const admin = ures && ures.results && ures.results[0];
        if (!admin || admin.role !== 'ADMIN') return jsonResponse({ error: 'forbidden' }, 403);
        const body = await request.json().catch(() => ({}));
        const email = body && String(body.email || '').trim().toLowerCase();
        const active = !!(body && body.active);
        if (!email) return jsonResponse({ error: 'email required' }, 400);
        if (!active) {
          // Prevent deactivating last active admin
          const row = await env.AUTH_DB.prepare(`SELECT role, is_active FROM users WHERE email = ?`).bind(email).all();
          const u = row.results && row.results[0];
          if (u && u.role === 'ADMIN' && u.is_active) {
            const cntRes = await env.AUTH_DB.prepare(`SELECT COUNT(*) AS c FROM users WHERE role = 'ADMIN' AND is_active = 1 AND email != ?`).bind(email).all();
            const c = cntRes.results && cntRes.results[0] && cntRes.results[0].c;
            if (!c) return jsonResponse({ error: 'cannot deactivate last active admin' }, 400);
          }
        }
        await env.AUTH_DB.prepare(`UPDATE users SET is_active = ? WHERE email = ?`).bind(active ? 1 : 0, email).run();
        return jsonResponse({ ok: true });
      }

      // Admin: update user role
      if (url.pathname === '/admin/users/role' && request.method === 'POST') {
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
        const admin = ures && ures.results && ures.results[0];
        if (!admin || admin.role !== 'ADMIN') return jsonResponse({ error: 'forbidden' }, 403);

        const body = await request.json().catch(() => ({}));
        const email = body && String(body.email || '').trim().toLowerCase();
        let role = (body && String(body.role || '').toUpperCase()) || '';
        if (!email) return jsonResponse({ error: 'email required' }, 400);
        if (!['USER', 'ADMIN'].includes(role)) return jsonResponse({ error: 'invalid role' }, 400);
        // Prevent self-demotion to USER to avoid accidental lockout
        if (email === sess.email && role !== 'ADMIN') {
          return jsonResponse({ error: 'cannot change own role to USER' }, 400);
        }
        // Prevent demoting last active admin
        if (role === 'USER') {
          const cur = await env.AUTH_DB.prepare(`SELECT role, is_active FROM users WHERE email = ?`).bind(email).all();
          const u = cur.results && cur.results[0];
          if (u && u.role === 'ADMIN' && u.is_active) {
            const cntRes = await env.AUTH_DB.prepare(`SELECT COUNT(*) AS c FROM users WHERE role = 'ADMIN' AND is_active = 1 AND email != ?`).bind(email).all();
            const c = cntRes.results && cntRes.results[0] && cntRes.results[0].c;
            if (!c) return jsonResponse({ error: 'cannot demote last active admin' }, 400);
          }
        }
        await env.AUTH_DB.prepare(`UPDATE users SET role = ? WHERE email = ?`).bind(role, email).run();
        return jsonResponse({ ok: true });
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

      // Attempt session refresh from remember cookie
      if (url.pathname === '/auth/refresh' && request.method === 'POST') {
        const rememberCookie = getCookie(request, 'remember');
        if (!rememberCookie) return jsonResponse({ error: 'no remember token' }, 401);
        const tokenHash = await sha256Hex(rememberCookie);
        const rres = await env.AUTH_DB.prepare(
          `SELECT email, expires_at, ua_hash FROM remember_tokens WHERE token_hash = ?`
        ).bind(tokenHash).all();
        const row = rres && rres.results && rres.results[0];
        if (!row) return jsonResponse({ error: 'invalid remember token' }, 401);
        if (Date.now() > row.expires_at) {
          await env.AUTH_DB.prepare(`DELETE FROM remember_tokens WHERE token_hash = ?`).bind(tokenHash).run();
          return jsonResponse({ error: 'remember expired' }, 401);
        }
        // Device binding: require same User-Agent
        const ua = request.headers.get('User-Agent') || '';
        const uaHash = await sha256Hex(ua);
        if (row.ua_hash && row.ua_hash !== uaHash) {
          return jsonResponse({ error: 'device mismatch' }, 401);
        }
        // rotate token
        const newToken = generateToken();
        const newHash = await sha256Hex(newToken);
        const now = Date.now();
        const exp = now + 90 * 24 * 60 * 60 * 1000;
        await env.AUTH_DB.prepare(
          `INSERT OR REPLACE INTO remember_tokens (token_hash, email, created_at, expires_at, ua_hash) VALUES (?, ?, ?, ?, ?)`
        ).bind(newHash, row.email, now, exp, uaHash).run();
        await env.AUTH_DB.prepare(`DELETE FROM remember_tokens WHERE token_hash = ?`).bind(tokenHash).run();
        const sessionId = generateToken();
        const sessionExpires = now + 1 * 24 * 60 * 60 * 1000;
        await env.AUTH_DB.prepare(
          `INSERT INTO sessions (session_id, email, created_at, expires_at) VALUES (?, ?, ?, ?)`
        ).bind(sessionId, row.email, now, sessionExpires).run();
        const set1 = `sessionId=${encodeURIComponent(sessionId)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${1 * 24 * 60 * 60}`;
        const set2 = `remember=${encodeURIComponent(newToken)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${90 * 24 * 60 * 60}`;
        return new Response(JSON.stringify({ ok: true, email: row.email }), {
          headers: { 'Content-Type': 'application/json', 'Set-Cookie': set1 + '\n' + set2 },
        });
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

      // Files API: list files for current user (or any user if admin)
      if (url.pathname === '/files/list' && request.method === 'GET') {
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
        const ures = await env.AUTH_DB.prepare(`SELECT role FROM users WHERE email = ?`).bind(sess.email).all();
        const user = ures.results && ures.results[0];
        const isAdmin = user && user.role === 'ADMIN';

        const targetEmail = url.searchParams.get('email');
        const owner = isAdmin && targetEmail ? targetEmail : sess.email;
        const prefix = `${owner}/`;
        const list = await env.FILES_BUCKET.list({ prefix });
        const files = (list.objects || []).map(o => ({ key: o.key, size: o.size, uploaded: o.uploaded }));
        return jsonResponse({ ok: true, files, owner });
      }

      // Files API: upload a file for current user only (admins cannot upload for others)
      if (url.pathname === '/files/upload' && request.method === 'POST') {
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
        const form = await request.formData();
        const file = form.get('file');
        if (!file || typeof file === 'string') return jsonResponse({ error: 'file required' }, 400);
        const owner = sess.email;
        const key = `${owner}/${file.name}`;
        const maxBytes = 10 * 1024 * 1024; // 10MB
        if (file.size > maxBytes) return jsonResponse({ error: 'file too large' }, 413);
        await env.FILES_BUCKET.put(key, file.stream(), { httpMetadata: { contentType: file.type || 'application/octet-stream' } });
        return jsonResponse({ ok: true, key, owner });
      }

      // Files API: delete a file for current user (or any user if admin)
      if (url.pathname === '/files/delete' && request.method === 'DELETE') {
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
        const ures = await env.AUTH_DB.prepare(`SELECT role FROM users WHERE email = ?`).bind(sess.email).all();
        const user = ures.results && ures.results[0];
        const isAdmin = user && user.role === 'ADMIN';

        const emailParam = url.searchParams.get('email');
        const nameParam = url.searchParams.get('name');
        if (!nameParam) return jsonResponse({ error: 'name required' }, 400);
        const owner = isAdmin && emailParam ? emailParam : sess.email;
        const key = `${owner}/${nameParam}`;
        await env.FILES_BUCKET.delete(key);
        return jsonResponse({ ok: true, key });
      }

      // Files API: create a presigned URL (tokenized via D1) for downloading a file
      if (url.pathname === '/files/presign' && request.method === 'POST') {
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
        const ures = await env.AUTH_DB.prepare(`SELECT role FROM users WHERE email = ?`).bind(sess.email).all();
        const user = ures.results && ures.results[0];
        const isAdmin = user && user.role === 'ADMIN';

        const params = await request.json().catch(() => ({}));
        const name = params && params.name;
        const targetEmail = params && params.email;
        if (!name) return jsonResponse({ error: 'name required' }, 400);
        const owner = isAdmin && targetEmail ? String(targetEmail) : sess.email;
        const key = `${owner}/${name}`;

        const head = await env.FILES_BUCKET.head(key);
        if (!head) return jsonResponse({ error: 'not found' }, 404);

        const token = generateToken();
        const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
        await env.AUTH_DB.prepare(
          `INSERT INTO file_links (token, owner, name, expires_at) VALUES (?, ?, ?, ?)`
        ).bind(token, owner, name, expiresAt).run();

        const origin = new URL(request.url).origin;
        const urlStr = `${origin}/files/download?token=${token}`;
        return jsonResponse({ ok: true, url: urlStr, expiresAt });
      }

      // Files API: download using a presigned token
      if (url.pathname === '/files/download' && request.method === 'GET') {
        const token = url.searchParams.get('token');
        if (!token) return jsonResponse({ error: 'token required' }, 400);
        const fres = await env.AUTH_DB.prepare(
          `SELECT token, owner, name, expires_at FROM file_links WHERE token = ?`
        ).bind(token).all();
        const link = fres && fres.results && fres.results[0];
        if (!link) return jsonResponse({ error: 'invalid token' }, 404);
        if (Date.now() > link.expires_at) {
          await env.AUTH_DB.prepare(`DELETE FROM file_links WHERE token = ?`).bind(token).run();
          return jsonResponse({ error: 'link expired' }, 410);
        }
        const key = `${link.owner}/${link.name}`;
        const obj = await env.FILES_BUCKET.get(key);
        if (!obj) return jsonResponse({ error: 'not found' }, 404);
        const disposition = `attachment; filename="${link.name}"`;
        return new Response(obj.body, {
          headers: {
            'Content-Type': obj.httpMetadata && obj.httpMetadata.contentType ? obj.httpMetadata.contentType : 'application/octet-stream',
            'Content-Disposition': disposition,
            'Cache-Control': 'no-store',
          },
        });
      }

      if (url.pathname === '/auth/signout' && request.method === 'POST') {
        const sessionId = getSessionIdFromRequest(request);
        if (sessionId) {
          await env.AUTH_DB.prepare(`DELETE FROM sessions WHERE session_id = ?`).bind(sessionId).run();
        }
        // clear remember token if present
        const rem = getCookie(request, 'remember');
        if (rem) {
          const h = await sha256Hex(rem).catch(() => null);
          if (h) {
            await env.AUTH_DB.prepare(`DELETE FROM remember_tokens WHERE token_hash = ?`).bind(h).run();
          }
        }
        const clearCookie = 'sessionId=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0';
        const clearRemember = 'remember=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0';
        return new Response(JSON.stringify({ ok: true }), {
          headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': clearCookie + '\n' + clearRemember,
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

function getCookie(request, name) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const parts = cookieHeader.split(';').map(s => s.trim());
  const found = parts.find(s => s.startsWith(name + '='));
  if (found) return decodeURIComponent(found.split('=')[1]);
  return null;
}

async function sendMagicLink(email, token, env, remember = false) {
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

  const link = `${APP_URL.replace(/\/$/, '')}/auth/verify?token=${token}&email=${encodeURIComponent(email)}${remember ? '&remember=1' : ''}`;

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

async function sha256Hex(input) {
  const enc = new TextEncoder();
  const data = enc.encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(digest);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}