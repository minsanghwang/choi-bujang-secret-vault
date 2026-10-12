// 5단계 가점: 로그인·로그아웃·세션 확인을 브라우저가 아니라 서버 함수가 맡습니다.
// 서버가 공식 Supabase SDK로 이메일·비밀번호 로그인을 하고, 받은 토큰은 브라우저 코드가 읽을 수 없는
// httpOnly 쿠키에만 담습니다. 비밀번호·토큰은 응답 본문과 로그에 넣지 않습니다.
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };

export const ACCESS_COOKIE = '__Host-aleph-at';
export const REFRESH_COOKIE = '__Host-aleph-rt';
const REFRESH_MAX_AGE = 7 * 24 * 60 * 60;

export function readCookies(header) {
  const out = {};
  if (typeof header !== 'string' || header.length > 8192) return out;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index > 0) out[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return out;
}
const cookie = (name, value, maxAge) =>
  `${name}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Strict`;
const clearCookies = () => [cookie(ACCESS_COOKIE, '', 0), cookie(REFRESH_COOKIE, '', 0)];

// 메모 API가 쓰는 요청자 토큰. Authorization 헤더가 있으면 그것만 쓰고(쿠키는 보지 않음),
// 없을 때만 로그인 쿠키의 접근 토큰을 씁니다.
export function sessionAuthorization(request) {
  const header = request.headers?.authorization;
  if (header !== undefined) return { value: header, fromCookie: false };
  const token = readCookies(request.headers?.cookie)[ACCESS_COOKIE];
  return token ? { value: `Bearer ${token}`, fromCookie: true } : { value: undefined, fromCookie: false };
}

// 쿠키로 인증된 쓰기 요청이 다른 사이트에서 온 것이면 거부합니다.
export function isSameSite(request) {
  const site = request.headers?.['sec-fetch-site'];
  if (site !== undefined) return site === 'same-origin' || site === 'none';
  const origin = request.headers?.origin;
  if (origin === undefined) return true;
  try { return new URL(origin).host === request.headers?.host; } catch { return false; }
}

const json = (response, status, body) => {
  response.setHeader('Cache-Control', 'no-store');
  response.status(status).json(body);
};
const fail = (response, status, error, extra = {}) => json(response, status, { error, ...extra });

const clientOptions = { auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false } };
function defaultClients() {
  const url = process.env.SUPABASE_URL;
  const publicKey = config.database?.publishableKey;
  if (typeof url !== 'string' || !url.startsWith('https://') || typeof publicKey !== 'string' || !publicKey) {
    throw new Error('config');
  }
  return {
    authClient: () => createClient(url, publicKey, clientOptions),
    adminClient: () => (process.env.SUPABASE_SECRET_KEY
      ? createClient(url, process.env.SUPABASE_SECRET_KEY, clientOptions) : null),
  };
}

function setSessionCookies(response, session) {
  const accessAge = Number.isSafeInteger(session.expires_in) && session.expires_in > 0 ? session.expires_in : 3600;
  response.setHeader('Set-Cookie', [
    cookie(ACCESS_COOKIE, session.access_token, accessAge),
    cookie(REFRESH_COOKIE, session.refresh_token, REFRESH_MAX_AGE),
  ]);
}

function readCredentials(request) {
  let body = request.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { return null; } }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const { email, password } = body;
  if (typeof email !== 'string' || typeof password !== 'string' || !email.trim() || !password
      || email.length > 254 || password.length > 200) return null;
  return { email: email.trim(), password };
}

// /api/auth/login (POST), /api/auth/logout (POST), /api/auth/session (GET)
export async function handleAuth(request, response, deps = {}) {
  const action = Array.isArray(request.query?.action) ? request.query.action[0] : request.query?.action;
  const allowed = { login: 'POST', logout: 'POST', session: 'GET' }[action];
  if (!allowed) return fail(response, 404, 'NOT_FOUND');
  if (request.method !== allowed) {
    response.setHeader('Allow', allowed);
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }
  if (allowed === 'POST' && !isSameSite(request)) return fail(response, 403, 'CROSS_SITE_BLOCKED');
  let clients;
  try { clients = deps.clients ?? defaultClients(); } catch { return fail(response, 500, 'AUTH_NOT_CONFIGURED'); }
  const cookies = readCookies(request.headers?.cookie);

  try {
    if (action === 'login') {
      const credentials = readCredentials(request);
      if (!credentials) return fail(response, 400, 'INVALID_LOGIN_REQUEST');
      const { data, error } = await clients.authClient().auth.signInWithPassword(credentials);
      if (error || !data?.session?.access_token || !data.session.refresh_token) {
        const status = error?.status === 429 ? 429 : 401;
        return fail(response, status, 'LOGIN_FAILED', { reason: String(error?.code ?? 'unknown') });
      }
      setSessionCookies(response, data.session);
      return json(response, 200, { email: String(data.user?.email ?? credentials.email) });
    }

    if (action === 'logout') {
      const access = cookies[ACCESS_COOKIE];
      if (access) {
        try { await clients.adminClient()?.auth.admin.signOut(access, 'local'); } catch { /* 쿠키는 어쨌든 지웁니다 */ }
      }
      response.setHeader('Set-Cookie', clearCookies());
      return json(response, 200, { ok: true });
    }

    // session: 접근 토큰이 유효하면 이메일을 돌려주고, 만료됐으면 새로고침 토큰으로 한 번 갱신합니다.
    const access = cookies[ACCESS_COOKIE];
    const refresh = cookies[REFRESH_COOKIE];
    if (access) {
      const { data, error } = await clients.authClient().auth.getUser(access);
      if (!error && data?.user?.email) return json(response, 200, { email: String(data.user.email) });
    }
    if (refresh) {
      const { data, error } = await clients.authClient().auth.refreshSession({ refresh_token: refresh });
      if (!error && data?.session?.access_token && data.session.refresh_token) {
        setSessionCookies(response, data.session);
        return json(response, 200, { email: String(data.user?.email ?? '') });
      }
    }
    if (access || refresh) response.setHeader('Set-Cookie', clearCookies());
    return fail(response, 401, 'LOGIN_REQUIRED');
  } catch {
    console.error('auth_request_failed');
    return fail(response, 502, 'AUTH_UPSTREAM_ERROR');
  }
}
