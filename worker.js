/**
 * Station 2 App — Cloudflare Worker
 *
 * Serves the static site (index.html, PDFs, service worker), gated behind a
 * shared-passcode lock screen, plus two API endpoints:
 *   POST /api/login   — checks a submitted passcode, sets a session cookie
 *   POST /api/notify  — sends a push notification when a new Pass It On
 *                        note is posted, without exposing the Firebase
 *                        service account credentials to the browser
 *
 * Required environment variables / secrets (set these in the Cloudflare
 * dashboard under Workers & Pages → station2-app → Settings → Variables and
 * Secrets — never commit them to the repo):
 *   FIREBASE_DATABASE_URL  (plain var)   e.g. https://station-2-app-default-rtdb.firebaseio.com
 *   FCM_PROJECT_ID         (plain var)   e.g. station-2-app
 *   FCM_CLIENT_EMAIL       (secret)      from the downloaded service-account JSON ("client_email")
 *   FCM_PRIVATE_KEY        (secret)      from the downloaded service-account JSON ("private_key"),
 *                                        pasted exactly as-is including the
 *                                        -----BEGIN PRIVATE KEY----- / -----END PRIVATE KEY----- lines
 *   SITE_PASSWORD          (secret)      the shared passcode the crew enters to get in
 *   SESSION_SECRET         (secret)      any long random string — used to sign session
 *                                        cookies so they can't be forged. Generate one
 *                                        with, e.g., a password manager's "generate
 *                                        password" feature (32+ random characters).
 *
 * Until SITE_PASSWORD and SESSION_SECRET are both set, the lock screen is
 * skipped entirely (fails open) so the site keeps working normally.
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/api/login' && request.method === 'POST') {
      return handleLogin(request, env);
    }

    const authed = await isAuthed(request, env);
    if (!authed) {
      return lockScreenResponse();
    }

    if (url.pathname === '/api/notify' && request.method === 'POST') {
      return handleNotify(request, env, ctx);
    }

    return env.ASSETS.fetch(request);
  }
};

/* ---- Passcode lock ---- */

const SESSION_COOKIE = 'station2_session';
const SESSION_MAX_AGE_SECONDS = 400 * 24 * 60 * 60; // 400 days — the max modern browsers allow

async function isAuthed(request, env) {
  if (!env.SITE_PASSWORD || !env.SESSION_SECRET) return true; // lock not configured yet -> open
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/(?:^|;\s*)station2_session=([^;]+)/);
  if (!match) return false;
  return verifySessionToken(match[1], env);
}

async function handleLogin(request, env) {
  if (!env.SITE_PASSWORD || !env.SESSION_SECRET) {
    return new Response(JSON.stringify({ ok: false, error: 'Password lock is not configured yet.' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return new Response('Bad request', { status: 400 });
  }

  const password = typeof body.password === 'string' ? body.password : '';
  if (!timingSafeEqual(password, env.SITE_PASSWORD)) {
    return new Response(JSON.stringify({ ok: false }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  const token = await makeSessionToken(env);
  const headers = new Headers({ 'Content-Type': 'application/json' });
  headers.append(
    'Set-Cookie',
    SESSION_COOKIE + '=' + token + '; Path=/; Max-Age=' + SESSION_MAX_AGE_SECONDS + '; HttpOnly; Secure; SameSite=Lax'
  );
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

async function makeSessionToken(env) {
  const expiry = Date.now() + SESSION_MAX_AGE_SECONDS * 1000;
  const payload = String(expiry);
  const sig = await hmacSign(payload, env.SESSION_SECRET);
  return payload + '.' + sig;
}

async function verifySessionToken(token, env) {
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [payload, sig] = parts;
  const expected = await hmacSign(payload, env.SESSION_SECRET);
  if (!timingSafeEqual(sig, expected)) return false;
  const expiry = parseInt(payload, 10);
  if (!expiry || Date.now() > expiry) return false;
  return true;
}

async function hmacSign(message, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return base64urlFromArrayBuffer(sigBuf);
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  // Compare full length regardless of an early mismatch so timing doesn't
  // leak how many leading characters were correct.
  const len = Math.max(a.length, b.length);
  let result = a.length === b.length ? 0 : 1;
  for (let i = 0; i < len; i++) {
    const ca = i < a.length ? a.charCodeAt(i) : 0;
    const cb = i < b.length ? b.charCodeAt(i) : 0;
    result |= ca ^ cb;
  }
  return result === 0;
}

function lockScreenResponse() {
  const html = '<!DOCTYPE html>' +
'<html lang="en"><head>' +
'<meta charset="UTF-8">' +
'<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
'<title>Station 2 — Locked</title>' +
'<style>' +
'body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#17140f;font-family:-apple-system,Helvetica,Arial,sans-serif;padding:20px;box-sizing:border-box;}' +
'.box{max-width:340px;width:100%;text-align:center;}' +
'h1{color:#e7dcc0;font-size:22px;margin:0 0 6px;}' +
'p{color:#8a8172;font-size:13px;margin:0 0 22px;}' +
'input{width:100%;box-sizing:border-box;padding:12px 14px;border-radius:6px;border:1px solid #3a352c;background:#221d16;color:#e7dcc0;font-size:16px;margin-bottom:12px;}' +
'button{width:100%;padding:12px;border-radius:6px;border:1px solid #4a3a1c;background:linear-gradient(180deg,#d4b878,#b8934f);color:#241c0d;font-weight:600;font-size:14px;cursor:pointer;}' +
'button:disabled{opacity:0.6;}' +
'.err{color:#cf5a26;font-size:12px;margin-top:10px;min-height:16px;}' +
'</style></head><body>' +
'<div class="box">' +
'<h1>Station 2</h1>' +
'<p>Enter the station passcode to continue.</p>' +
'<form id="f">' +
'<input id="pw" type="password" autocomplete="current-password" placeholder="Passcode" autofocus>' +
'<button type="submit" id="btn">Unlock</button>' +
'<p class="err" id="err"></p>' +
'</form>' +
'</div>' +
'<script>' +
"document.getElementById('f').addEventListener('submit', async function(e){" +
"e.preventDefault();" +
"var pw = document.getElementById('pw').value;" +
"var err = document.getElementById('err');" +
"var btn = document.getElementById('btn');" +
"err.textContent = '';" +
"btn.disabled = true;" +
"try{" +
"var res = await fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ password: pw }) });" +
"if(res.ok){ location.reload(); return; }" +
"err.textContent = 'Wrong passcode — try again.';" +
"}catch(e2){ err.textContent = 'Connection error — try again.'; }" +
"btn.disabled = false;" +
"});" +
'</script>' +
'</body></html>';
  return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
}

async function handleNotify(request, env, ctx) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return new Response('Bad request', { status: 400 });
  }

  const unit = typeof body.unit === 'string' ? body.unit.slice(0, 40) : '';
  const text = typeof body.text === 'string' ? body.text.slice(0, 500) : '';
  if (!unit || !text) {
    return new Response('Bad request', { status: 400 });
  }

  const required = ['FIREBASE_DATABASE_URL', 'FCM_PROJECT_ID', 'FCM_CLIENT_EMAIL', 'FCM_PRIVATE_KEY'];
  const missing = required.filter((key) => !env[key]);
  if (missing.length) {
    console.warn('Pass It On notify: missing env vars — skipping send.', missing.join(', '));
    return new Response('ok', { status: 202 });
  }

  // Respond right away; do the actual sending in the background so posting
  // a note never waits on push delivery.
  ctx.waitUntil(sendNotifications(unit, text, env));
  return new Response('ok', { status: 202 });
}

async function sendNotifications(unit, text, env) {
  try {
    const dbUrl = env.FIREBASE_DATABASE_URL.replace(/\/$/, '');
    const tokensRes = await fetch(dbUrl + '/pushTokens.json');
    if (!tokensRes.ok) return;
    const tokensObj = await tokensRes.json();
    const tokens = tokensObj ? Object.keys(tokensObj) : [];
    if (!tokens.length) return;

    const accessToken = await getGoogleAccessToken(env);
    const unitLabel = unit.charAt(0).toUpperCase() + unit.slice(1);
    const title = 'Pass It On — ' + unitLabel;
    const bodyText = text.length > 120 ? text.slice(0, 117) + '…' : text;

    await Promise.all(tokens.map(async (token) => {
      try {
        const res = await fetch(
          'https://fcm.googleapis.com/v1/projects/' + env.FCM_PROJECT_ID + '/messages:send',
          {
            method: 'POST',
            headers: {
              'Authorization': 'Bearer ' + accessToken,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              message: {
                token: token,
                notification: { title: title, body: bodyText },
                data: { unit: unit }
              }
            })
          }
        );
        if (!res.ok) {
          const errText = await res.text();
          // Token no longer valid (uninstalled, permission revoked, etc.) — clean it up.
          if (errText.indexOf('UNREGISTERED') !== -1 || errText.indexOf('INVALID_ARGUMENT') !== -1) {
            await fetch(dbUrl + '/pushTokens/' + token + '.json', { method: 'DELETE' });
          } else {
            console.error('FCM send failed:', res.status, errText);
          }
        }
      } catch (e) {
        console.error('FCM send failed for token', e);
      }
    }));
  } catch (e) {
    console.error('sendNotifications failed', e);
  }
}

/* ---- Google OAuth2 access token via a signed service-account JWT ---- */

let cachedToken = null;
let cachedTokenExpiry = 0;

async function getGoogleAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && now < cachedTokenExpiry - 60) {
    return cachedToken;
  }

  const header = { alg: 'RS256', typ: 'JWT' };
  const claimSet = {
    iss: env.FCM_CLIENT_EMAIL,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600
  };

  const encHeader = base64url(JSON.stringify(header));
  const encClaim = base64url(JSON.stringify(claimSet));
  const signingInput = encHeader + '.' + encClaim;

  const key = await importPrivateKey(env.FCM_PRIVATE_KEY);
  const signatureBuf = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    new TextEncoder().encode(signingInput)
  );
  const jwt = signingInput + '.' + base64urlFromArrayBuffer(signatureBuf);

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=' + encodeURIComponent(jwt)
  });

  if (!tokenRes.ok) {
    const errText = await tokenRes.text();
    throw new Error('Failed to get Google access token: ' + errText);
  }

  const tokenJson = await tokenRes.json();
  cachedToken = tokenJson.access_token;
  cachedTokenExpiry = now + (tokenJson.expires_in || 3600);
  return cachedToken;
}

async function importPrivateKey(pem) {
  const pemContents = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s/g, '');
  const binaryDer = base64ToArrayBuffer(pemContents);
  return crypto.subtle.importKey(
    'pkcs8',
    binaryDer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function base64url(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlFromArrayBuffer(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
