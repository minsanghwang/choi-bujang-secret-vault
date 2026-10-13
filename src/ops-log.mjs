// 12단계: 자료 API가 응답한 결과를 "가려서" 서버 표(defense_ops_log)에 남기는 감싸개입니다. 탈환 작전실의 수치는 이 기록에서만 나옵니다.
// 남기는 것: 시각, 요청 ID, 메서드, 경로 이름(:id 형태), 응답 상태, 거부 이유 코드, 인증 방식, 사용자의 가명(해시 12자).
// 남기지 않는 것: 사용자 ID 원문·이메일·토큰·쿠키·요청과 응답 본문·메모 제목과 내용·쿼리 문자열.
// 기록이 실패해도 원래 응답은 그대로 나갑니다(기록은 응답을 바꾸지 않고, 응답을 보내기 전에 먼저 씁니다: 서버 함수는 응답 뒤에 멈출 수 있음).
import { createHash, randomUUID } from 'node:crypto';
import { ACCESS_COOKIE } from './auth-service.mjs';

const TABLE = 'defense_ops_log';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']);
const REASON = /^[a-z0-9_]{1,40}$/u;
const WRITE_TIMEOUT_MS = 1500;

// 사용자 ID의 가명: 해시 앞 12자. 같은 사용자는 같은 값이지만 원래 ID를 알아낼 수 없고, 화면에는 그 일부만 보입니다.
export const actorOf = userId => createHash('sha256').update(String(userId).toLowerCase(), 'utf8').digest('hex').slice(0, 12);

export function requestIdOf(request) {
  const given = request.headers?.['x-request-id'];
  return typeof given === 'string' && UUID.test(given) ? given.toLowerCase() : randomUUID();   // UUID 모양만 받습니다
}
const authKind = request => {
  const headers = request.headers ?? {};
  if (typeof headers.authorization === 'string') return 'bearer';
  return typeof headers.cookie === 'string' && headers.cookie.includes(`${ACCESS_COOKIE}=`) ? 'cookie' : 'none';
};
const reasonOf = (headerReason, body) => {
  const text = typeof headerReason === 'string' ? headerReason : typeof body?.error === 'string' ? body.error.toLowerCase() : null;
  return text && REASON.test(text) ? text : null;
};

async function insert(row, deps) {
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!key || !process.env.SUPABASE_URL) return false;
  const url = new URL(`/rest/v1/${TABLE}`, process.env.SUPABASE_URL);
  if (url.protocol !== 'https:') return false;
  const headers = { apikey: key, 'Content-Type': 'application/json', Prefer: 'return=minimal' };
  if (key.startsWith('eyJ')) headers.Authorization = `Bearer ${key}`;
  const upstream = await (deps.fetch ?? fetch)(url, { method: 'POST', headers, body: JSON.stringify(row), signal: AbortSignal.timeout(WRITE_TIMEOUT_MS) });
  return upstream.ok;
}

// route: 'notes', 'notes/:id', 'notices', 'notices/:id', 'restore', 'device' 처럼 고정된 이름만 씁니다(실제 경로의 ID는 남기지 않음).
export function withOpsLog(route, handler, deps = {}) {
  return async function logged(request, response) {
    const requestId = requestIdOf(request);
    response.setHeader('X-Request-Id', requestId);
    const method = METHODS.has(String(request.method).toUpperCase()) ? String(request.method).toUpperCase() : 'OTHER';
    let denyReason = null;
    let done = false;
    const record = async (status, body) => {
      if (done) return;
      done = true;
      try {
        await insert({ request_id: requestId, method, route, status, reason: reasonOf(denyReason, body), auth: authKind(request),
          actor: request.opsActor ? actorOf(request.opsActor) : null }, deps);
      } catch { /* 기록 실패는 응답에 영향을 주지 않습니다. */ }
    };
    const proxy = new Proxy(response, {
      get(target, property) {
        if (property === 'setHeader') {
          return (name, value) => { if (String(name).toLowerCase() === 'x-deny-reason') denyReason = value; return target.setHeader(name, value); };
        }
        if (property === 'status') {
          return code => {
            const inner = target.status(code);
            return {
              json: async body => { await record(code, body); return inner.json(body); },
              end: async (...args) => { await record(code, null); return inner.end(...args); },
            };
          };
        }
        const value = target[property];
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    return handler(request, proxy);
  };
}
