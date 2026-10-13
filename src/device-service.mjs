// 11단계: 기기 승인 요청과 상태 조회.  GET·POST /api/device  (서비스: notes 자료실 화면)
// - 승인 여부는 서버의 비공개 표(defense_devices)가 정합니다. 이 API는 승인을 요청하고 결과를 읽을 뿐 승인하지 않습니다.
//   승인(pending → approved)과 해제(→ revoked)는 운영 측이 DB에서만 바꿉니다. 화면 버튼·본문 값·쿼리로는 권한이 생기지 않습니다.
// - 브라우저에는 서버가 준 읽을 수 없는(HttpOnly) 쿠키 하나만 둡니다. 기기 키·토큰·승인 상태를 localStorage 등에 넣지 않습니다.
//   쿠키 값은 서버가 만든 무작위 핸들이고, DB에는 그 SHA-256 지문만 저장합니다. 핸들 원문은 응답·로그·DB 어디에도 남기지 않습니다.
// - 이 상태는 앱 화면이 자료를 열지 말지 정하는 표시용입니다. 운영 엔진의 기기 등록(deviceRegistered)을 대신하지 않으며,
//   판정기 계약에 기기 승인 값이 없으므로 src/decider.mjs는 이 상태를 읽지 않습니다.
import { createHash, randomBytes } from 'node:crypto';
import { readCookies } from './auth-service.mjs';
import { requireLogin } from './notes-service.mjs';

const TABLE = 'defense_devices';
export const DEVICE_COOKIE = '__Host-aleph-dv';
const COOKIE_MAX_AGE = 30 * 24 * 60 * 60;
const MAX_ACTIVE = 5;                                  // 한 사용자의 승인 대기·승인 기기 상한
const HANDLE = /^[A-Za-z0-9_-]{43}$/u;                 // 무작위 32바이트(base64url)
const STATES = new Set(['pending', 'approved', 'revoked']);

const sha256 = text => createHash('sha256').update(text, 'utf8').digest('hex');
const json = (response, status, body) => { response.setHeader('Cache-Control', 'no-store'); response.status(status).json(body); };
const fail = (response, status, error, reason) => {
  if (reason) response.setHeader('X-Deny-Reason', reason);
  return json(response, status, { error });
};

async function rest(method, query, payload, deps) {
  const key = process.env.SUPABASE_SECRET_KEY;
  const url = new URL(`/rest/v1/${TABLE}`, process.env.SUPABASE_URL);
  if (url.protocol !== 'https:' || !key) throw new Error('config');
  for (const [name, value] of Object.entries(query)) url.searchParams.set(name, value);
  const headers = { apikey: key, Accept: 'application/json', Prefer: 'return=representation' };
  if (key.startsWith('eyJ')) headers.Authorization = `Bearer ${key}`;
  if (payload !== undefined) headers['Content-Type'] = 'application/json';
  const upstream = await (deps.fetch ?? fetch)(url, { method, headers, signal: AbortSignal.timeout(8000),
    body: payload === undefined ? undefined : JSON.stringify(payload) });
  let rows = null;
  try { rows = await upstream.json(); } catch { /* 본문 없음 */ }
  return { ok: upstream.ok, status: upstream.status, rows };
}

// POST 본문은 비어 있어야 합니다. status·approved·role 같은 값은 어떤 것도 받지 않습니다.
function bodyIsEmpty(request) {
  let body = request.body;
  if (body === undefined || body === null || body === '') return true;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { return false; } }
  return Boolean(body) && typeof body === 'object' && !Array.isArray(body) && Object.keys(body).length === 0;
}

const view = row => ({ state: STATES.has(row?.status) ? row.status : 'none',
  ...(row ? { deviceId: row.id, requestedAt: row.requested_at ?? null, decidedAt: row.decided_at ?? null } : {}) });

export async function handleDevice(request, response, deps = {}) {
  if (request.method !== 'GET' && request.method !== 'POST') {
    response.setHeader('Allow', 'GET, POST');
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }
  const who = await requireLogin(request, response, deps);
  if (!who) return undefined;
  const owner = who.userId.toLowerCase();
  const handle = readCookies(request.headers?.cookie)[DEVICE_COOKIE];
  try {
    // 이 브라우저의 핸들 지문 + 로그인한 사용자가 모두 맞는 행만 "내 기기"입니다. 다른 사람의 쿠키는 없는 것으로 봅니다.
    let mine = null;
    if (typeof handle === 'string' && HANDLE.test(handle)) {
      const found = await rest('GET', { select: 'id,status,requested_at,decided_at',
        handle_sha256: `eq.${sha256(handle)}`, owner_id: `eq.${owner}`, limit: '1' }, undefined, deps);
      if (!found.ok || !Array.isArray(found.rows)) return fail(response, 502, 'DEVICE_UPSTREAM_ERROR');
      mine = found.rows[0] ?? null;
    }
    if (request.method === 'GET') return json(response, 200, view(mine));

    if (!bodyIsEmpty(request)) return fail(response, 400, 'INVALID_DEVICE_REQUEST');
    if (mine) return json(response, 200, view(mine));        // 이미 요청한 기기는 새 행을 만들지 않고 지금 상태만 알려 줍니다.

    const active = await rest('GET', { select: 'id', owner_id: `eq.${owner}`, status: 'in.(pending,approved)', limit: String(MAX_ACTIVE) }, undefined, deps);
    if (!active.ok || !Array.isArray(active.rows)) return fail(response, 502, 'DEVICE_UPSTREAM_ERROR');
    if (active.rows.length >= MAX_ACTIVE) return fail(response, 429, 'DEVICE_LIMIT', 'device_limit');

    const fresh = randomBytes(32).toString('base64url');
    // 상태는 항상 pending으로만 만듭니다. 서버 코드에도 approved로 쓰는 경로가 없습니다.
    const created = await rest('POST', {}, { owner_id: owner, handle_sha256: sha256(fresh), status: 'pending' }, deps);
    const row = Array.isArray(created.rows) ? created.rows[0] : null;
    if (!created.ok || !row) return fail(response, 502, 'DEVICE_UPSTREAM_ERROR');
    response.setHeader('Set-Cookie', `${DEVICE_COOKIE}=${fresh}; Max-Age=${COOKIE_MAX_AGE}; Path=/; HttpOnly; Secure; SameSite=Strict`);
    return json(response, 201, view({ ...row, status: 'pending' }));
  } catch {
    console.error('device_request_failed');
    return fail(response, 502, 'DEVICE_UPSTREAM_ERROR');
  }
}
