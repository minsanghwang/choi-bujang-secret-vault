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
const logRow = (n, extra = {}) => ({ at: iso(n), request_id: `${String(n).padStart(8, '0')}-1111-4111-8111-111111111111`, method: 'GET', route: 'notes', status: 200, reason: null, auth: 'bearer', actor: 'a1b2c3d4e5f6', ...extra });
// 표 이름별 가짜 서버. 조회한 열(select)을 기록해 메모 제목·내용을 읽지 않았는지 확인합니다.
function world({ log = [], devices = [], audit = [], backups = [], missing = [] } = {}) {
  const w = { selects: [], tables: { defense_ops_log: log, defense_devices: devices, defense_restore_audit: audit, defense_notes_backup: backups } };
  w.fetch = async url => {
    const u = new URL(url);
    const table = u.pathname.split('/').pop();
    w.selects.push({ table, select: u.searchParams.get('select') });
    if (missing.includes(table)) return new Response('{}', { status: 404 });
    let rows = w.tables[table];
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
  assert.equal(body.unrun.attacks41.label, '미실행');
  assert.doesNotMatch(JSON.stringify(body), /통과|passed|clear/iu);                  // 성공 문구를 만들지 않음
}));

test('탐지 요약은 서버 기록의 GET 사건에 detect()를 실제로 적용하고, 120건을 넘을 때만 회수 제안이다', () => withEnv(async () => {
  const burst = n => Array.from({ length: n }, (_, i) => logRow(i + 1, { actor: 'abcdef012345' }));
  const calm = (await summary(world({ log: burst(120) }))).body;                     // 정확히 120건은 의심하지 않음
  assert.deepEqual([calm.detection.observed.getEvents, calm.detection.observed.busiestWindow, calm.detection.observed.result], [120, 120, { action: 'observe' }]);
  assert.equal(calm.revocation.proposals.count, 0);
  const hot = (await summary(world({ log: burst(121) }))).body;
  assert.equal(hot.detection.observed.result.action, 'propose_revocation');
  assert.equal(hot.detection.observed.result.reasonCode, 'burst_read');
  assert.ok(!JSON.stringify(hot).includes('abcdef012345'));                           // 대상은 가려서만 보임
  assert.equal(hot.revocation.proposals.count, 1);
  const mixed = (await summary(world({ log: [...burst(100), ...Array.from({ length: 50 }, (_, i) => logRow(200 + i, { actor: 'other0000000', method: 'POST' }))] }))).body;
  assert.equal(mixed.detection.observed.result.action, 'observe');                    // 다른 사용자·GET이 아닌 요청은 합산하지 않음
}));

test('회수 상태·복구 요약은 기기 표·복원 감사·사본 표의 줄 수와 같다', () => withEnv(async () => {
  const w = world({ devices: [{ status: 'approved' }, { status: 'pending' }, { status: 'pending' }, { status: 'revoked' }],
    audit: [{ outcome: 'planned' }, { outcome: 'started' }, { outcome: 'restored' }, { outcome: 'denied' }, { outcome: 'denied' }], backups: Array.from({ length: 5 }, (_, i) => ({ note_id: String(i) })) });
  const body = (await summary(w)).body;
  assert.deepEqual([body.revocation.devices.pending, body.revocation.devices.approved, body.revocation.devices.revoked, body.revocation.devices.total], [2, 1, 1, 4]);
  assert.deepEqual([body.recovery.restoreAudit.planned, body.recovery.restoreAudit.restored, body.recovery.restoreAudit.denied, body.recovery.restoreAudit.total], [1, 1, 2, 5]);
  assert.equal(body.recovery.backups.count, 5);
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
