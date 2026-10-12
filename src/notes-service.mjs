// 3~4단계: 로그인한 사용자의 가상 메모 추가·조회·수정·삭제.
// 요청자 신원은 src/verify-login.mjs가 토큰에서 확인한 값만 씁니다.
// 4단계: 읽기·수정·삭제 전에 DB 행의 owner_id를 읽어 검증된 사용자 ID와 비교하고,
// 주인이 다르거나 비어 있으면 기본 거부합니다. URL·본문의 owner_id·userId·role은 믿지 않습니다.
import config from '../aleph.config.json' with { type: 'json' };
import { isSameSite, sessionAuthorization } from './auth-service.mjs';
import { createLoginVerifier } from './verify-login.mjs';

const TABLE = 'defense_notes';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const MAX_TITLE = 200;
const MAX_BODY = 5000;

const json = (response, status, body) => {
  response.setHeader('Cache-Control', 'no-store');
  response.status(status).json(body);
};
const fail = (response, status, error) => json(response, status, { error });

let cachedVerifier = { key: null, verify: null };
function defaultVerifier() {
  const key = process.env.SUPABASE_SECRET_KEY;
  if (cachedVerifier.key !== key || !cachedVerifier.verify) {
    cachedVerifier = { key, verify: createLoginVerifier({ config, supabaseSecretKey: key }) };
  }
  return cachedVerifier.verify;
}

function restUrl(query = {}) {
  const url = new URL(`/rest/v1/${TABLE}`, process.env.SUPABASE_URL);
  if (url.protocol !== 'https:' || !process.env.SUPABASE_SECRET_KEY) throw new Error('config');
  for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
  return url;
}
async function rest(method, query, payload, deps) {
  const key = process.env.SUPABASE_SECRET_KEY;
  const headers = { apikey: key, Accept: 'application/json', Prefer: 'return=representation' };
  if (key.startsWith('eyJ')) headers.Authorization = `Bearer ${key}`;
  if (payload !== undefined) headers['Content-Type'] = 'application/json';
  const upstream = await (deps.fetch ?? fetch)(restUrl(query), {
    method, headers, signal: AbortSignal.timeout(8000),
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
  let rows = null;
  try { rows = await upstream.json(); } catch { /* 본문이 없거나 JSON이 아님 */ }
  return { status: upstream.status, ok: upstream.ok, rows };
}
const view = row => ({ id: String(row.id), title: String(row.title), body: String(row.content) });

// 로그인 확인. 실패하면 응답을 이미 보냈고 null을 돌려줍니다. 자료는 한 글자도 읽지 않습니다.
async function requireLogin(request, response, deps) {
  let verify;
  try {
    verify = (deps.verify ?? defaultVerifier());
    restUrl();
  } catch {
    fail(response, 500, 'NOTES_NOT_CONFIGURED');
    return null;
  }
  // Authorization 헤더가 있으면 그것만 검사하고, 없을 때만 서버가 심어 둔 로그인 쿠키를 씁니다.
  const auth = sessionAuthorization(request);
  if (auth.fromCookie && request.method !== 'GET' && !isSameSite(request)) {
    fail(response, 403, 'CROSS_SITE_BLOCKED');
    return null;
  }
  let who = null;
  try { who = await verify(auth.value); } catch { who = null; }
  if (!who || !UUID.test(who.userId ?? '')) {
    response.setHeader('WWW-Authenticate', 'Bearer');
    fail(response, 401, 'LOGIN_REQUIRED');
    return null;
  }
  return who;
}

function readBody(request) {
  let body = request.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return null; }
  }
  return body && typeof body === 'object' && !Array.isArray(body) ? body : null;
}
function readNote(request) {
  const body = readBody(request);
  if (!body) return null;
  const { title, body: text } = body;
  if (typeof title !== 'string' || !title.trim() || title.length > MAX_TITLE
      || typeof text !== 'string' || text.length > MAX_BODY) return null;
  return { title: title.trim(), content: text, id: body.id };
}

async function upstreamFailed(response, upstream) {
  console.error('notes_upstream_status', upstream.status);
  return fail(response, 502, 'NOTES_UPSTREAM_ERROR');
}

// /api/notes : GET 목록, POST 추가
export async function handleCollection(request, response, deps = {}) {
  if (!['GET', 'POST'].includes(request.method)) {
    response.setHeader('Allow', 'GET, POST');
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }
  const who = await requireLogin(request, response, deps);
  if (!who) return undefined;
  try {
    if (request.method === 'GET') {
      // 내 메모만 돌려줍니다. 주인이 없거나 다른 사람 것인 행은 읽지 않습니다.
      const upstream = await rest('GET', {
        select: 'id,title,content',
        owner_id: `eq.${who.userId}`,
        order: 'position.asc,created_at.asc',
      }, undefined, deps);
      if (!upstream.ok || !Array.isArray(upstream.rows)) return await upstreamFailed(response, upstream);
      return json(response, 200, upstream.rows.map(view));
    }
    const note = readNote(request);
    if (!note) return fail(response, 400, 'INVALID_NOTE');
    if (note.id !== undefined && (typeof note.id !== 'string' || !UUID.test(note.id))) {
      return fail(response, 400, 'INVALID_ID');
    }
    const row = { owner_id: who.userId, title: note.title, content: note.content };
    if (note.id !== undefined) row.id = note.id.toLowerCase();
    const upstream = await rest('POST', {}, row, deps);
    if (upstream.status === 409) return fail(response, 409, 'ID_ALREADY_USED');
    if (!upstream.ok || !Array.isArray(upstream.rows) || !upstream.rows[0]) {
      return await upstreamFailed(response, upstream);
    }
    return json(response, 201, { id: String(upstream.rows[0].id) });
  } catch {
    console.error('notes_request_failed');
    return fail(response, 502, 'NOTES_UPSTREAM_ERROR');
  }
}

// 소유자 비교. 행이 없으면 404, 주인이 내가 아니면(비어 있는 경우 포함) 403으로 기본 거부합니다.
const sameUser = (owner, userId) => typeof owner === 'string' && owner.toLowerCase() === userId.toLowerCase();
const OWNER_KEYS = ['owner_id', 'ownerId', 'userId', 'user_id'];

// /api/notes/:id : GET 한 건, PUT 수정, DELETE 삭제
export async function handleItem(request, response, deps = {}) {
  if (!['GET', 'PUT', 'DELETE'].includes(request.method)) {
    response.setHeader('Allow', 'GET, PUT, DELETE');
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }
  const who = await requireLogin(request, response, deps);
  if (!who) return undefined;
  const id = Array.isArray(request.query?.id) ? request.query.id[0] : request.query?.id;
  if (typeof id !== 'string' || !UUID.test(id)) return fail(response, 400, 'INVALID_ID');
  const target = { id: `eq.${id.toLowerCase()}` };
  // 본문 검사는 DB를 읽기 전에 합니다. 소유자를 바꾸려는 요청은 거부합니다.
  let note = null;
  if (request.method === 'PUT') {
    const body = readBody(request);
    if (body && OWNER_KEYS.some(key => key in body && !sameUser(body[key], who.userId))) {
      return fail(response, 403, 'OWNER_CHANGE_FORBIDDEN');
    }
    note = readNote(request);
    if (!note) return fail(response, 400, 'INVALID_NOTE');
  }
  try {
    // 기존 행의 owner_id를 읽어 검증된 사용자와 비교합니다.
    const found = await rest('GET', { ...target, select: 'id,title,content,owner_id' }, undefined, deps);
    if (!found.ok || !Array.isArray(found.rows)) return await upstreamFailed(response, found);
    const row = found.rows[0];
    if (!row) return fail(response, 404, 'NOT_FOUND');
    if (!sameUser(row.owner_id, who.userId)) return fail(response, 403, 'FORBIDDEN');
    if (request.method === 'GET') return json(response, 200, view(row));

    // 쓰기 조건에도 owner_id를 넣어, 비교 뒤 주인이 바뀌어도 남의 행은 바꾸거나 지우지 않습니다.
    const guard = { ...target, owner_id: `eq.${who.userId}` };
    let upstream;
    if (request.method === 'DELETE') {
      upstream = await rest('DELETE', { ...guard, select: 'id' }, undefined, deps);
    } else {
      // 새 행의 소유자도 검증된 사용자로 고정합니다.
      upstream = await rest('PATCH', { ...guard, select: 'id,title,content' },
        { title: note.title, content: note.content, owner_id: who.userId }, deps);
    }
    if (!upstream.ok || !Array.isArray(upstream.rows)) return await upstreamFailed(response, upstream);
    if (!upstream.rows[0]) return fail(response, 404, 'NOT_FOUND');
    if (request.method === 'DELETE') {
      response.setHeader('Cache-Control', 'no-store');
      return response.status(204).end();
    }
    return json(response, 200, view(upstream.rows[0]));
  } catch {
    console.error('notes_request_failed');
    return fail(response, 502, 'NOTES_UPSTREAM_ERROR');
  }
}
