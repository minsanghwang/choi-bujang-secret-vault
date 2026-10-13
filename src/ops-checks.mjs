// 12단계: 1~12단계의 정상·금지 요청을 "실제로 보내고" 한 표로 남기는 절차입니다(npm run ops:table).
// 표의 한 줄 = 요청 하나: 단계, 정상/금지, 기대 결과, 실제 API 결과(HTTP 상태·거부 이유), 요청 ID, 확인 시각, 서버 기록 대조.
// 규칙
//  - 실제로 보낸 요청의 결과만 "일치/불일치"로 적습니다. 보내지 못했거나 이 절차가 보낼 수 없는 것은 모두 "미실행"과 이유입니다.
//  - 심판·운영 엔진이 보내는 시험(6·7·9단계의 판정·탐지·회수, 41종 총공세)은 이 절차가 만들거나 대신 채우지 않습니다.
//  - 로그인 토큰은 메모리에서만 쓰고 표·파일·화면 어디에도 남기지 않습니다. 메모 제목·내용도 표에 넣지 않습니다.
import { randomUUID } from 'node:crypto';

export const RESULT = Object.freeze({ match: '일치', mismatch: '불일치', notRun: '미실행' });
const DENIED = status => status === 401 || status === 403;
const DENIED_OR_HIDDEN = status => status === 401 || status === 403 || status === 404;

export const subOf = token => {
  try { return JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url').toString('utf8')).sub ?? null; } catch { return null; }
};

const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
export const forgedBearer = identityProvider => `Bearer ${b64({ alg: 'ES256', typ: 'JWT' })}.${b64({ iss: identityProvider?.issuer,
  aud: identityProvider?.audience, role: 'authenticated', sub: '00000000-0000-4000-8000-000000000000', exp: Math.floor(Date.now() / 1000) + 3600 })}.${Buffer.from('forged').toString('base64url')}`;

// 로그인 토큰은 Supabase 로그인(비밀번호 방식)으로만 받고, 값은 이 함수 밖으로 나가지 않는 변수에만 둡니다.
export async function signIn(config, email, password, fetchFn = fetch) {
  if (!email || !password) return null;
  try {
    const response = await fetchFn(new URL('/auth/v1/token?grant_type=password', config.database.url), {
      method: 'POST', headers: { apikey: config.database.publishableKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }), signal: AbortSignal.timeout(10000) });
    if (!response.ok) return null;
    const data = await response.json();
    return typeof data.access_token === 'string' ? data.access_token : null;
  } catch { return null; }
}

// 확인 항목. as: none | forged | A | B. expect(status, data)가 true이면 기대와 일치합니다.
// build(ctx)는 요청 내용을 만들고, null을 돌려주면 그 줄은 미실행(이유는 skip)입니다.
export function buildChecks(config) {
  return [
    { stage: 1, name: '정적 /data.json 공개', kind: 'forbidden', as: 'none', noServer: true, method: 'GET', path: () => '/data.json',
      expected: '404이거나 메모가 보이지 않음', expect: (s, d) => s === 404 || !(d && (d.sampleMarker === config.sampleMarker || (Array.isArray(d) && d.length > 0))) },
    { stage: 3, name: '비로그인 메모 목록', kind: 'forbidden', as: 'none', method: 'GET', path: () => '/api/notes',
      expected: '401 또는 403', expect: DENIED },
    { stage: 3, name: '서명 없는 가짜 토큰 메모 목록', kind: 'forbidden', as: 'forged', method: 'GET', path: () => '/api/notes',
      expected: '401 또는 403', expect: DENIED },
    { stage: 3, name: 'A 로그인 메모 목록', kind: 'normal', as: 'A', method: 'GET', path: () => '/api/notes',
      expected: '200과 메모 목록(배열)', expect: (s, d) => s === 200 && Array.isArray(d) },
    { stage: 4, name: 'A 가상 메모 추가', kind: 'normal', as: 'A', method: 'POST', path: () => '/api/notes',
      body: () => ({ title: 'ops-table 점검용 가상 메모', body: '자동 생성·삭제되는 가상 메모입니다.' }),
      expected: '201과 새 메모 번호', expect: (s, d) => s === 201 && typeof d?.id === 'string', after: (ctx, d) => { ctx.noteId = d.id; } },
    { stage: 4, name: 'A 자기 메모 읽기', kind: 'normal', as: 'A', method: 'GET', needs: 'noteId', path: ctx => `/api/notes/${ctx.noteId}`,
      expected: '200', expect: s => s === 200 },
    { stage: 4, name: 'A 자기 메모 수정', kind: 'normal', as: 'A', method: 'PUT', needs: 'noteId', path: ctx => `/api/notes/${ctx.noteId}`,
      body: () => ({ title: 'ops-table 점검용 가상 메모', body: '수정됨(가상).' }), expected: '200', expect: s => s === 200 },
    { stage: 8, name: 'B가 A의 메모 읽기', kind: 'forbidden', as: 'B', method: 'GET', needs: 'noteId+B', path: ctx => `/api/notes/${ctx.noteId}`,
      expected: '403(또는 404)이고 메모가 없음', expect: (s, d) => DENIED_OR_HIDDEN(s) && !d?.title },
    { stage: 8, name: 'B가 A의 메모 수정', kind: 'forbidden', as: 'B', method: 'PUT', needs: 'noteId+B', path: ctx => `/api/notes/${ctx.noteId}`,
      body: () => ({ title: 'B의 시도(가상)', body: 'B의 시도(가상)' }), expected: '403(또는 404)', expect: DENIED_OR_HIDDEN },
    { stage: 8, name: 'B가 A의 메모 삭제', kind: 'forbidden', as: 'B', method: 'DELETE', needs: 'noteId+B', path: ctx => `/api/notes/${ctx.noteId}`,
      expected: '403(또는 404)', expect: DENIED_OR_HIDDEN },
    { stage: 8, name: 'A 공지 목록 읽기', kind: 'normal', as: 'A', method: 'GET', path: () => '/api/notices',
      expected: '200과 공지 목록(배열)', expect: (s, d) => s === 200 && Array.isArray(d), after: (ctx, d) => { const first = d.find(item => typeof item?.id === 'string'); if (first) ctx.notice = { id: first.id, title: first.title, body: first.body }; } },
    { stage: 8, name: '일반 학생이 강사 공지 수정', kind: 'forbidden', as: 'A', method: 'PUT', needs: 'notice', path: ctx => `/api/notices/${ctx.notice.id}`,
      body: ctx => ({ title: ctx.notice.title, body: ctx.notice.body }), expected: '403', expect: s => s === 403 },
    { stage: 10, name: 'A가 B 소유로 복원 미리보기', kind: 'forbidden', as: 'A', method: 'POST', needs: 'noteId+B', path: () => '/api/restore',
      body: ctx => ({ id: ctx.noteId, ownerId: ctx.subB }), expected: '403(소유자 불일치)', expect: s => s === 403 },
    { stage: 11, name: '비로그인 기기 상태 조회', kind: 'forbidden', as: 'none', method: 'GET', path: () => '/api/device',
      expected: '401 또는 403', expect: DENIED },
    { stage: 11, name: 'A 기기 상태 조회(쿠키 없는 직접 호출)', kind: 'normal', as: 'A', method: 'GET', path: () => '/api/device',
      expected: '200과 상태 값', expect: (s, d) => s === 200 && typeof d?.state === 'string' },
    { stage: 12, name: '비로그인 작전실 요약', kind: 'forbidden', as: 'none', noServer: true, method: 'GET', path: () => '/api/ops',
      expected: '401 또는 403', expect: (s, d) => DENIED(s) && d?.schema === undefined },
    { stage: 12, name: 'A 작전실 요약', kind: 'normal', as: 'A', noServer: true, method: 'GET', path: () => '/api/ops',
      expected: '200과 aleph.ops.v1', expect: (s, d) => s === 200 && d?.schema === 'aleph.ops.v1' },
    // 정리: 이 절차가 만든 가상 메모를 지웁니다(정상 요청).
    { stage: 4, name: 'A 자기 메모 삭제(정리)', kind: 'normal', as: 'A', method: 'DELETE', needs: 'noteId', path: ctx => `/api/notes/${ctx.noteId}`,
      expected: '204(또는 200)', expect: s => s === 204 || s === 200 },
  ];
}

// 이 절차가 보낼 수 없는 단계: 심판·운영 엔진이 보냅니다. 표에는 미실행으로만 남깁니다.
export const NOT_RUN_ROWS = Object.freeze([
  { stage: 5, name: '공개 키로 원본 저장소 직접 조회', kind: 'forbidden', expected: '401·403 또는 빈 목록', reason: 'direct' },
  { stage: 6, name: '미등록 기기 요청 판정', kind: 'forbidden', expected: 'deny · device_not_registered', reason: '판정기 호출은 운영 엔진·심판이 합니다(decider:test는 가상 연습).' },
  { stage: 7, name: '이상 접속 추가 확인(step_up)', kind: 'forbidden', expected: 'step_up', reason: '재판정과 재로그인 사건은 운영 엔진·심판이 보냅니다.' },
  { stage: 9, name: '조회 120건 초과 복합 사건 회수', kind: 'forbidden', expected: 'propose_revocation · burst_read', reason: '사건 전달과 접속 회수 집행은 운영 엔진이 합니다(detect:test는 가상 연습).' },
  { stage: 12, name: '41종 총공세', kind: 'forbidden', expected: '41종 모두 방어', reason: '심판이 실행합니다. 이 표는 그 결과를 만들거나 대신 채우지 않습니다.' },
]);

const text = (value, max = 80) => String(value ?? '').replace(/[\r\n|]+/gu, ' ').slice(0, max);

export async function runChecks({ config, tokens = {}, fetch: fetchFn = fetch, now = () => new Date(), uuid = randomUUID, checks = buildChecks(config) } = {}) {
  const app = new URL(config.publicAppUrl);
  const ctx = { subB: tokens.B ? subOf(tokens.B) : null };
  const rows = [];

  async function send(check, headers, body, requestId) {
    const url = new URL(check.path(ctx), app);
    const response = await fetchFn(url, { method: check.method, redirect: 'error', signal: AbortSignal.timeout(15000),
      headers: { ...headers, 'X-Request-Id': requestId, ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
    let data = null;
    if (/json/iu.test(response.headers?.get?.('content-type') ?? '')) { try { data = await response.json(); } catch { /* JSON 아님 */ } }
    return { status: response.status, data, requestId: response.headers?.get?.('x-request-id') ?? requestId };
  }
  async function serverRecord(requestId, status) {
    if (!tokens.A) return { state: '확인 못함', note: 'A 계정이 없어 서버 기록을 조회하지 못함' };
    try {
      const url = new URL(`/api/ops?requestId=${requestId}`, app);
      const response = await fetchFn(url, { method: 'GET', redirect: 'error', signal: AbortSignal.timeout(15000), headers: { Authorization: `Bearer ${tokens.A}` } });
      if (response.status !== 200) return { state: '확인 못함', note: `기록 조회 HTTP ${response.status}` };
      const data = await response.json();
      if (!data?.record) return { state: '기록 없음', note: '서버 기록에 이 요청 ID가 없음' };
      return data.record.status === status ? { state: '일치', note: `서버 기록 HTTP ${data.record.status}` }
        : { state: '불일치', note: `서버 기록 HTTP ${data.record.status}, 응답 HTTP ${status}` };
    } catch { return { state: '확인 못함', note: '기록 조회 요청 실패' }; }
  }

  for (const check of checks) {
    const base = { stage: check.stage, kind: check.kind === 'normal' ? '정상' : '금지', name: check.name, request: `${check.method} ${check.path({ noteId: ':id', notice: { id: ':id' } })}`, expected: check.expected };
    const needsB = check.needs?.includes('+B') || check.as === 'B';
    const needsNote = check.needs?.startsWith('noteId');
    const missing = (check.as === 'A' && !tokens.A) ? 'A 로그인 환경변수가 없음'
      : (needsB && !tokens.B) ? 'B 로그인 환경변수가 없음'
      : (needsNote && !ctx.noteId) ? '앞 단계의 가상 메모가 만들어지지 않음'
      : (check.needs === 'notice' && !ctx.notice) ? '읽을 수 있는 강사 공지가 없음' : null;
    if (missing) { rows.push({ ...base, actual: null, requestId: null, checkedAt: null, result: RESULT.notRun, serverRecord: '해당 없음', note: `미실행: ${missing}` }); continue; }
    const headers = check.as === 'A' ? { Authorization: `Bearer ${tokens.A}` } : check.as === 'B' ? { Authorization: `Bearer ${tokens.B}` }
      : check.as === 'forged' ? { Authorization: forgedBearer(config.identityProvider) } : {};
    const requestId = uuid();
    const checkedAt = now().toISOString();
    let reply;
    try { reply = await send(check, headers, check.body?.(ctx), requestId); }
    catch { rows.push({ ...base, actual: null, requestId, checkedAt, result: RESULT.notRun, serverRecord: '해당 없음', note: '미실행: 요청을 보내지 못함(네트워크·주소 확인)' }); continue; }
    const ok = Boolean(check.expect(reply.status, reply.data));
    if (ok && check.after) { try { check.after(ctx, reply.data); } catch { /* 다음 줄이 미실행으로 남음 */ } }
    const reason = reply.data && typeof reply.data.error === 'string' ? ` ${text(reply.data.error, 40)}` : '';
    const record = check.noServer ? { state: '해당 없음', note: '이 주소는 서버 요청 기록 대상이 아님(정적 파일·작전실 조회)' } : await serverRecord(reply.requestId, reply.status);
    rows.push({ ...base, actual: `HTTP ${reply.status}${reason}`, requestId: reply.requestId, checkedAt, result: ok ? RESULT.match : RESULT.mismatch,
      serverRecord: record.state, note: record.note });
  }
  for (const item of NOT_RUN_ROWS) {
    rows.push({ stage: item.stage, kind: item.kind === 'normal' ? '정상' : '금지', name: item.name, request: '—', expected: item.expected,
      actual: null, requestId: null, checkedAt: null, result: RESULT.notRun, serverRecord: '해당 없음',
      note: item.reason === 'direct' ? '미실행: 원본 저장소 직접 조회는 npm run bundle의 src/attack-check.mjs가 보냅니다(이 표는 보내지 않음).' : `미실행: ${item.reason}` });
  }
  return rows.sort((a, b) => a.stage - b.stage);
}

export function summarize(rows) {
  const count = name => rows.filter(row => row.result === name).length;
  return { total: rows.length, match: count(RESULT.match), mismatch: count(RESULT.mismatch), notRun: count(RESULT.notRun),
    serverRecordMismatch: rows.filter(row => row.serverRecord === '불일치' || row.serverRecord === '기록 없음').length };
}

export function toMarkdown(rows, { commit = null } = {}) {
  const head = '| 단계 | 구분 | 요청 | 기대 결과 | 실제 API 결과 | 판정 | 서버 기록 | 요청 ID | 확인 시각 |\n|---|---|---|---|---|---|---|---|---|';
  const lines = rows.map(row => `| ${row.stage} | ${row.kind} | ${text(row.name, 40)}<br>${text(row.request)} | ${text(row.expected)} | ${row.actual ?? text(row.note, 120)} | ${row.result} | ${row.serverRecord} | ${row.requestId ?? '—'} | ${row.checkedAt ?? '—'} |`);
  const sum = summarize(rows);
  return [`커밋: ${commit ?? '확인 안 함'}`, '', head, ...lines, '',
    `합계 ${sum.total}줄: 일치 ${sum.match} · 불일치 ${sum.mismatch} · 미실행 ${sum.notRun}`,
    '41종 총공세: 미실행(심판이 실행합니다. 이 표는 통과로 표시하지 않습니다).'].join('\n');
}
