import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ACCESS_COOKIE } from '../src/auth-service.mjs';
import { DEVICE_COOKIE, sha256 } from '../src/device-gate.mjs';
import { handleOps } from '../src/ops-service.mjs';

const A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const NOW = Date.parse('2026-10-13T12:00:00Z');
const verify = async authorization => (authorization === 'Bearer a.a.a' || authorization === 'Bearer a.c.c' ? { kind: 'student', userId: A } : null);
const asA = { authorization: 'Bearer a.a.a' };
const HANDLE = 'H'.repeat(43);

async function withEnv(fn) {
  const names = ['SUPABASE_URL', 'SUPABASE_SECRET_KEY'];
  const saved = Object.fromEntries(names.map(n => [n, process.env[n]]));
  Object.assign(process.env, { SUPABASE_URL: 'https://abc.supabase.co', SUPABASE_SECRET_KEY: 'fake-test-key-not-real-0123456789' });
  try { return await fn(); } finally { for (const n of names) { if (saved[n] === undefined) delete process.env[n]; else process.env[n] = saved[n]; } }
}
const iso = offsetSeconds => new Date(NOW - offsetSeconds * 1000).toISOString();
const logRow = (n, extra = {}) => ({ id: n, at: iso(n), request_id: `${String(n).padStart(8, '0')}-1111-4111-8111-111111111111`, method: 'GET', route: 'notes', status: 200, reason: null, auth: 'bearer', actor: 'a1b2c3d4e5f6', ...extra });
// 표 이름별 가짜 서버. 조회한 열(select)을 기록해 메모 제목·내용을 읽지 않았는지 확인합니다.
function world({ log = [], devices = [], audit = [], backups = [], missing = [] } = {}) {
  const w = { selects: [], tables: { defense_ops_log: log, defense_devices: devices, defense_restore_audit: audit, defense_notes_backup: backups } };
  w.fetch = async url => {
    const u = new URL(url);
    const table = u.pathname.split('/').pop();
    w.selects.push({ table, select: u.searchParams.get('select') });
    if (missing.includes(table)) return new Response('{}', { status: 404 });
    let rows = w.tables[table];
    const upTo = u.searchParams.get('id');                                      // 맨 끝 번호까지만 읽는 조회(id=lte.N)
    if (upTo) rows = rows.filter(row => row.id <= Number(upTo.replace(/^lte\./u, '')));
    if (u.searchParams.get('order') === 'id.desc') rows = [...rows].sort((a, b) => b.id - a.id);
    const id = u.searchParams.get('request_id');
    if (id) rows = rows.filter(row => row.request_id === id.replace(/^eq\./u, ''));
    return new Response(JSON.stringify(rows.slice(0, Number(u.searchParams.get('limit') ?? Infinity))), { status: 200 });
  };
  return w;
}
async function call(w, request, extra = {}) {
  const out = { headers: new Map() };
  await handleOps(request, { setHeader: (k, v) => out.headers.set(k.toLowerCase(), v),
    status: code => { out.status = code; return { json: data => { out.body = data; } }; } }, { verify, fetch: w.fetch, now: () => NOW, ...extra });
  return out;
}
const summary = (w, headers = asA) => call(w, { method: 'GET', headers, query: {} });

test('로그인 없이는 401이고 기록 표를 읽지 않으며, GET 외의 메서드는 405다', () => withEnv(async () => {
  const w = world();
  assert.equal((await call(w, { method: 'GET', headers: {}, query: {} })).status, 401);
  assert.equal((await call(w, { method: 'POST', headers: asA })).status, 405);
  assert.equal(w.selects.length, 0);
}));

test('브라우저 로그인은 승인된 기기 쿠키가 있어야 하고, 없으면 403이며 기록 표를 읽지 않는다', () => withEnv(async () => {
  const w = world({ log: [logRow(1)] });
  const cookie = `${ACCESS_COOKIE}=a.c.c; ${DEVICE_COOKIE}=${HANDLE}`;
  const denied = await call(w, { method: 'GET', headers: { cookie }, query: {} }, { deviceApproved: async () => false });
  assert.deepEqual([denied.status, denied.body], [403, { error: 'DEVICE_NOT_APPROVED' }]);
  assert.equal(w.selects.length, 0);
  assert.equal((await call(w, { method: 'GET', headers: { cookie }, query: {} }, { deviceApproved: async () => true })).status, 200);
}));

test('화면의 수치는 가린 서버 기록과 같다: 합계 = 허용+거부+오류 = 경로별 합 = 기록 줄 수', () => withEnv(async () => {
  const log = [logRow(1), logRow(2, { status: 403, reason: 'owner_mismatch' }), logRow(3, { status: 401, reason: 'login_required', actor: null, auth: 'none' }),
    logRow(4, { route: 'restore', method: 'POST', status: 404, reason: 'backup_not_found' }), logRow(5, { route: 'restore', method: 'POST', status: 200 }), logRow(6, { status: 503 })];
  const res = await summary(world({ log }));
  const r = res.body.requests;
  assert.equal(res.status, 200);
  assert.deepEqual([r.total, r.allowed, r.denied, r.errors], [6, 2, 3, 1]);
  assert.equal(r.total, r.allowed + r.denied + r.errors);
  assert.equal(r.byRoute.reduce((sum, item) => sum + item.total, 0), r.total);
  assert.deepEqual(r.byRoute.map(item => [item.route, item.total, item.allowed, item.denied, item.errors]), [['notes', 4, 1, 2, 1], ['restore', 2, 1, 1, 0]]);
  assert.equal(r.records.length, 6);                                              // 가린 기록 줄 수 = 합계(30줄 이내)
  assert.equal(r.label, '확인됨(서버 기록)');
  assert.equal(r.total, log.length);                                              // 기록 표를 직접 센 값과 같다(24시간 같은 자르기 없음)
  assert.deepEqual([r.newestSeq, r.oldestSeq], [6, 1]);
  assert.deepEqual(r.records.map(item => item.seq), [6, 5, 4, 3, 2, 1]);          // 화면의 번호로 표의 줄을 찾을 수 있다
  assert.match(r.note, /\/api\/auth\/\*.*정적 파일/u);                // 기록하지 않는 요청을 화면이 밝힌다
}));

test('가린 기록에는 점검 이름(attackId)이 그대로 남고, 점검 이름별로 줄 수와 최근 줄을 찾을 수 있다', () => withEnv(async () => {
  const log = [logRow(1, { status: 401, reason: 'login_required', actor: null, auth: 'none', attack_id: 'anonymous_api_notes_read' }),
    logRow(2, { status: 401, reason: 'login_required', actor: null, auth: 'bearer', attack_id: 'forged_token_notes_read' }),
    logRow(3, { route: 'ops', status: 401, reason: 'login_required', actor: null, auth: 'none', attack_id: 'ops_summary_without_login' }),
    logRow(4, { status: 401, reason: 'login_required', actor: null, auth: 'none', attack_id: 'anonymous_api_notes_read' }),
    logRow(5)];
  const w = world({ log });
  const r = (await summary(w)).body.requests;
  assert.deepEqual(r.records.map(item => item.attackId), [null, 'anonymous_api_notes_read', 'ops_summary_without_login', 'forged_token_notes_read', 'anonymous_api_notes_read']);
  assert.deepEqual(r.byAttack.map(item => [item.attackId, item.rows, item.latest.seq, item.latest.route, item.latest.status]),
    [['anonymous_api_notes_read', 2, 4, 'notes', 401], ['forged_token_notes_read', 1, 2, 'notes', 401], ['ops_summary_without_login', 1, 3, 'ops', 401]]);
  assert.equal(r.byAttack.reduce((sum, item) => sum + item.rows, 0), log.filter(row => row.attack_id).length);   // 점검 이름별 줄 수 합 = 이름이 붙은 기록 줄 수
  assert.ok(w.selects.some(item => item.table === 'defense_ops_log' && item.select.includes('attack_id')));
  const one = await call(w, { method: 'GET', headers: asA, query: { requestId: log[1].request_id } });
  assert.equal(one.body.record.attackId, 'forged_token_notes_read');            // 요청 ID로 찾은 한 줄에도 점검 이름이 있다
}));

test('오래된 기록도 24시간 같은 기준으로 자르지 않고 표 전체를 센다', () => withEnv(async () => {
  const old = Array.from({ length: 7 }, (_, i) => logRow(i + 1, { at: '2025-01-01T00:00:00.000Z' }));
  const r = (await summary(world({ log: old }))).body.requests;
  assert.equal(r.total, 7);
  assert.equal(r.oldestAt, '2025-01-01T00:00:00.000Z');
}));

test('읽는 동안 새 줄이 들어와도 맨 끝 번호까지만 세어 합계가 어긋나지 않는다', () => withEnv(async () => {
  const w = world({ log: [logRow(1), logRow(2)] });
  const base = w.fetch;
  w.fetch = async url => {
    const res = await base(url);
    if (new URL(url).searchParams.get('limit') === '1') w.tables.defense_ops_log.push(logRow(3));   // 번호를 정한 직후 새 줄이 생김
    return res;
  };
  const r = (await summary(w)).body.requests;
  assert.deepEqual([r.total, r.allowed + r.denied + r.errors, r.newestSeq], [2, 2, 2]);
}));

test('가린 기록은 30줄까지만 보여 주고, 그때도 합계는 읽은 기록 전체와 같다', () => withEnv(async () => {
  const log = Array.from({ length: 45 }, (_, i) => logRow(i + 1, { status: i % 3 === 0 ? 403 : 200 }));
  const r = (await summary(world({ log }))).body.requests;
  assert.equal(r.total, 45);
  assert.equal(r.records.length, 30);
  assert.equal(r.allowed + r.denied + r.errors, 45);
}));

test('응답에는 사용자 ID·가명·전체 요청 ID·메모 제목과 내용·토큰이 없다', () => withEnv(async () => {
  const log = [logRow(1, { actor: 'a1b2c3d4e5f6' })];
  const w = world({ log, devices: [{ status: 'approved' }], audit: [{ outcome: 'restored' }], backups: [{ note_id: 'x' }] });
  const text = JSON.stringify((await summary(w)).body);
  assert.ok(!text.includes('a1b2c3d4e5f6'));                                       // 가명 원문
  assert.ok(!text.includes('11111111-1111-4111-8111-111111111111'));              // 전체 요청 ID
  assert.ok(!text.includes(A));
  assert.doesNotMatch(text, /"title"|"content"|"body"|Bearer|eyJ/u);
  assert.match(text, /00000001…/u);                                                // 요청 ID는 앞 8자만
  for (const { select } of w.selects) assert.doesNotMatch(select, /title|content|owner_id|handle/u);   // 제목·내용·소유자·핸들을 읽지 않음
}));

test('판정기 규칙과 탐지 규칙은 코드에서 읽음, 판정·사건·회수 집행의 실제 결과는 미실행으로 구분한다', () => withEnv(async () => {
  const body = (await summary(world())).body;
  assert.equal(body.decider.label, '코드에서 읽음');
  assert.deepEqual(body.decider.ruleIds, ['device_registered', 'zone_access', 'step_up_required']);
  assert.deepEqual(body.decider.routes.map(item => item.route), ['GET /notes/:id', 'PUT /notes/:id', 'PUT /notices/:id']);
  assert.equal(body.decider.realDecisions.label, '미실행');
  assert.equal(body.detection.rule.source, '코드에서 읽음');
  assert.equal(body.detection.engineDelivery.label, '미실행');
  assert.equal(body.revocation.enforcement.label, '미실행');
  assert.equal(body.revocation.proposals.label, '미실행');                              // 회수 제안 건수를 만들어 채우지 않음
  assert.equal(body.detection.engineResult.label, '미실행');
  assert.equal(body.unrun.attacks41.label, '미실행');
  assert.doesNotMatch(JSON.stringify(body), /통과|passed|clear|propose_revocation|"action"/iu);                  // 성공 문구를 만들지 않음
}));

test('탐지 요약은 서버 기록의 GET 줄 수만 세고, 판정·회수 제안은 만들어 채우지 않는다', () => withEnv(async () => {
  const burst = n => Array.from({ length: n }, (_, i) => logRow(i + 1, { actor: 'abcdef012345' }));
  for (const n of [120, 121, 300]) {                                                  // 120을 넘어도 우리 쪽이 회수 제안을 만들지 않는다
    const d = (await summary(world({ log: burst(n) }))).body.detection;
    assert.deepEqual([d.observed.getRows, d.observed.getRowsWithUser, d.observed.getRowsWithoutUser, d.observed.users, d.observed.busiestWindowRows], [n, n, 0, 1, n]);
    assert.equal(d.engineResult.label, '미실행');
    assert.equal(d.observed.result, undefined);
  }
  const mixed = (await summary(world({ log: [...burst(100), ...Array.from({ length: 50 }, (_, i) => logRow(200 + i, { actor: 'other0000000', method: 'POST' })),
    ...Array.from({ length: 3 }, (_, i) => logRow(300 + i, { actor: null, auth: 'none', status: 401 }))] }))).body.detection;
  assert.deepEqual([mixed.observed.getRows, mixed.observed.getRowsWithUser, mixed.observed.getRowsWithoutUser, mixed.observed.users], [103, 100, 3, 1]);   // GET이 아닌 요청은 세지 않고, 비로그인 GET은 따로 보임
  assert.ok(!JSON.stringify(mixed).includes('abcdef012345'));                         // 사용자 가명은 보이지 않음
}));

test('회수 상태·복구 요약은 기기 표·복원 감사·사본 표의 줄 수와 같다', () => withEnv(async () => {
  const w = world({ devices: [{ status: 'approved' }, { status: 'pending' }, { status: 'pending' }, { status: 'revoked' }],
    audit: [{ outcome: 'planned' }, { outcome: 'started' }, { outcome: 'restored' }, { outcome: 'denied' }, { outcome: 'denied' }, { outcome: 'trace' }, { outcome: 'weird' }], backups: Array.from({ length: 5 }, (_, i) => ({ note_id: String(i) })) });
  const body = (await summary(w)).body;
  const dv = body.revocation.devices;
  assert.deepEqual([dv.pending, dv.approved, dv.revoked, dv.other, dv.total], [2, 1, 1, 0, 4]);
  const ra = body.recovery.restoreAudit;
  assert.deepEqual([ra.planned, ra.restored, ra.denied, ra.trace, ra.other, ra.total], [1, 1, 2, 1, 1, 7]);   // 감사 표 전체 줄 수(추적 줄도 포함)
  assert.equal(ra.total, ra.planned + ra.started + ra.restored + ra.denied + ra.failed + ra.trace + ra.other);
  assert.equal(body.recovery.backups.rows, 5);
  assert.deepEqual([body.recovery.policy.version, body.recovery.policy.sha256Prefix], ['v1', '364f5a32af39']);
}));

test('표를 읽지 못하면 수치를 만들어 내지 않고 "확인하지 못함"으로 표시한다', () => withEnv(async () => {
  const body = (await summary(world({ missing: ['defense_ops_log', 'defense_devices'] }))).body;
  assert.equal(body.requests.label, '확인하지 못함');
  assert.equal(body.requests.total, null);
  assert.equal(body.detection.observed.label, '확인하지 못함');
  assert.equal(body.revocation.devices.label, '확인하지 못함');
  assert.equal(body.recovery.backups.label, '확인됨(서버 기록)');                     // 읽은 표만 확인됨
}));

test('요청 ID로 서버 기록 한 줄을 조회하고, 모양이 틀린 ID는 400이다', () => withEnv(async () => {
  const w = world({ log: [logRow(7, { status: 403, reason: 'not_owner' })] });
  const id = w.tables.defense_ops_log[0].request_id;
  const hit = await call(w, { method: 'GET', headers: asA, query: { requestId: id } });
  assert.deepEqual([hit.status, hit.body.record.status, hit.body.record.reason, hit.body.record.requestId], [200, 403, 'not_owner', id]);
  const miss = await call(w, { method: 'GET', headers: asA, query: { requestId: '99999999-9999-4999-8999-999999999999' } });
  assert.deepEqual(miss.body.record, null);
  assert.equal((await call(w, { method: 'GET', headers: asA, query: { requestId: 'x' } })).status, 400);
}));
