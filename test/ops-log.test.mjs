import assert from 'node:assert/strict';
import { test } from 'node:test';
import { actorOf, requestIdOf, withOpsLog } from '../src/ops-log.mjs';

const REQ_ID = '12345678-1234-4234-8234-123456789abc';
const USER = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

async function withEnv(fn) {
  const names = ['SUPABASE_URL', 'SUPABASE_SECRET_KEY'];
  const saved = Object.fromEntries(names.map(n => [n, process.env[n]]));
  Object.assign(process.env, { SUPABASE_URL: 'https://abc.supabase.co', SUPABASE_SECRET_KEY: 'fake-test-key-not-real-0123456789' });
  try { return await fn(); } finally { for (const n of names) { if (saved[n] === undefined) delete process.env[n]; else process.env[n] = saved[n]; } }
}
// 응답을 보낸 순서를 events에 남겨 "기록이 응답보다 먼저인지" 확인합니다.
function harness(handler, { failLog = false } = {}) {
  const events = [];
  const rows = [];
  const fetch = async (url, init) => {
    events.push('log');
    if (failLog) throw new Error('db down');
    rows.push(JSON.parse(init.body));
    return new Response(null, { status: 201 });
  };
  const out = { headers: new Map() };
  const response = { setHeader: (k, v) => out.headers.set(k.toLowerCase(), v),
    status: code => ({ json: data => { events.push('sent'); out.status = code; out.body = data; }, end: () => { events.push('sent'); out.status = code; out.ended = true; } }) };
  const run = request => withOpsLog('notes/:id', handler, { fetch })(request, response);
  return { run, out, events, rows };
}

test('응답을 보내기 전에 결과를 먼저 기록하고, 메서드·경로 이름·상태·이유·인증 방식만 남긴다', () => withEnv(async () => {
  const h = harness((request, response) => { response.setHeader('X-Deny-Reason', 'owner_mismatch'); return response.status(403).json({ error: 'FORBIDDEN', secret: '메모 본문' }); });
  await h.run({ method: 'get', headers: { authorization: 'Bearer a.b.c', 'x-request-id': REQ_ID }, url: `/api/notes/${USER}?x=1`, body: { title: '제목', body: '본문' } });
  assert.deepEqual(h.events, ['log', 'sent']);                                     // 기록 → 응답
  assert.equal(h.out.status, 403);
  assert.deepEqual(h.out.body, { error: 'FORBIDDEN', secret: '메모 본문' });        // 응답은 그대로
  assert.equal(h.out.headers.get('x-request-id'), REQ_ID);
  assert.deepEqual(h.rows, [{ request_id: REQ_ID, method: 'GET', route: 'notes/:id', status: 403, reason: 'owner_mismatch', auth: 'bearer', actor: null, attack_id: null }]);
  assert.ok(!JSON.stringify(h.rows).match(/Bearer|제목|본문|a\.b\.c|\?x=1/u));       // 토큰·본문·실제 경로의 ID·쿼리가 없음
}));

test('이유는 X-Deny-Reason이 없으면 오류 문구를 소문자로 쓰고, 모양이 맞지 않으면 남기지 않는다', () => withEnv(async () => {
  const a = harness((request, response) => response.status(401).json({ error: 'LOGIN_REQUIRED' }));
  await a.run({ method: 'POST', headers: {} });
  assert.deepEqual([a.rows[0].reason, a.rows[0].auth, a.rows[0].method], ['login_required', 'none', 'POST']);
  const b = harness((request, response) => response.status(400).json({ error: '잘못된 요청 문구!' }));
  await b.run({ method: 'PROPFIND', headers: { cookie: '__Host-aleph-at=x.y.z' } });
  assert.deepEqual([b.rows[0].reason, b.rows[0].auth, b.rows[0].method], [null, 'cookie', 'OTHER']);
  const c = harness((request, response) => response.status(204).end());
  await c.run({ method: 'DELETE', headers: {} });
  assert.deepEqual([c.rows[0].status, c.out.ended], [204, true]);
}));

test('사용자는 가명(해시 12자)으로만 남고, 요청 ID는 UUID 모양만 받는다', () => withEnv(async () => {
  const h = harness((request, response) => response.status(200).json([]));
  const request = { method: 'GET', headers: { 'x-request-id': 'not-a-uuid' } };
  Object.defineProperty(request, 'opsActor', { value: USER });
  await h.run(request);
  assert.equal(h.rows[0].actor, actorOf(USER));
  assert.match(h.rows[0].actor, /^[0-9a-f]{12}$/u);
  assert.ok(!JSON.stringify(h.rows).includes(USER));
  assert.match(h.rows[0].request_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);   // 잘못된 값은 새 UUID로 바뀜
  assert.notEqual(requestIdOf({ headers: {} }), requestIdOf({ headers: {} }));
}));

test('기록 표를 쓰지 못해도 원래 응답은 그대로 나간다', () => withEnv(async () => {
  const h = harness((request, response) => response.status(200).json([{ id: '1' }]), { failLog: true });
  await h.run({ method: 'GET', headers: {} });
  assert.equal(h.out.status, 200);
  assert.deepEqual(h.out.body, [{ id: '1' }]);
}));

test('비밀 키가 없으면 기록을 건너뛰고 응답은 그대로다', async () => {
  const saved = process.env.SUPABASE_SECRET_KEY;
  delete process.env.SUPABASE_SECRET_KEY;
  try {
    const h = harness((request, response) => response.status(200).json({ ok: true }));
    await h.run({ method: 'GET', headers: {} });
    assert.equal(h.out.status, 200);
    assert.equal(h.rows.length, 0);
  } finally { if (saved !== undefined) process.env.SUPABASE_SECRET_KEY = saved; }
});

test('점검 이름 헤더(X-Attack-Id) 값만 남기고, 다른 헤더·User-Agent·쿼리와 모양이 틀린 이름은 남기지 않는다', () => withEnv(async () => {
  const h = harness((request, response) => response.status(401).json({ error: 'LOGIN_REQUIRED' }));
  await h.run({ method: 'GET', headers: { 'x-attack-id': 'anonymous_api_notes_read', 'x-aleph-run': 'secret-run-value', 'x-vercel-id': 'iad1::x', 'user-agent': 'x', host: 'h',
    'sec-fetch-mode': 'cors', 'x-forwarded-for': '1.2.3.4', 'x-judge-token': 'tok_should_not_be_stored' } });
  assert.equal(h.rows[0].attack_id, 'anonymous_api_notes_read');
  assert.deepEqual(Object.keys(h.rows[0]).sort(), ['actor', 'attack_id', 'auth', 'method', 'reason', 'request_id', 'route', 'status']);   // 헤더 이름·UA·쿼리 열 없음
  assert.ok(!JSON.stringify(h.rows).match(/secret-run-value|tok_should_not_be_stored|1\.2\.3\.4|x-aleph-run|x-judge-token/u));
  const bad = harness((request, response) => response.status(401).json({ error: 'LOGIN_REQUIRED' }));
  await bad.run({ method: 'GET', headers: { 'x-attack-id': 'Bad Id!<script>' } });
  assert.equal(bad.rows[0].attack_id, null);
  const merged = harness((request, response) => response.status(401).json({ error: 'LOGIN_REQUIRED' }));
  await merged.run({ method: 'GET', headers: { 'x-attack-id': 'anonymous_api_notes_read, anonymous_api_notes_read' } });   // 같은 이름이 둘 합쳐져 와도 첫 값만 읽음
  assert.equal(merged.rows[0].attack_id, 'anonymous_api_notes_read');
}));

test('새 열이 아직 없는 DB가 거부해도 그 열 없이 한 번 더 써서 기록이 끊기지 않는다', () => withEnv(async () => {
  const rows = [];
  const fetch = async (url, init) => {
    const row = JSON.parse(init.body);
    if ('attack_id' in row) return new Response('{"message":"column not found"}', { status: 400 });
    rows.push(row);
    return new Response(null, { status: 201 });
  };
  const out = { headers: new Map() };
  const response = { setHeader: (k, v) => out.headers.set(k.toLowerCase(), v), status: () => ({ json: () => {} }) };
  await withOpsLog('notes', (request, res) => res.status(200).json([]), { fetch })({ method: 'GET', headers: { 'x-attack-id': 'a' } }, response);
  assert.equal(rows.length, 1);
  assert.ok(!('ua' in rows[0]) && !('qs' in rows[0]));
  assert.deepEqual(Object.keys(rows[0]).sort(), ['actor', 'auth', 'method', 'reason', 'request_id', 'route', 'status']);
}));

test('User-Agent·쿼리 문자열·쿠키·토큰은 기록에 남지 않는다', () => withEnv(async () => {
  const h = harness((request, response) => response.status(401).json({ error: 'LOGIN_REQUIRED' }));
  await h.run({ method: 'GET', url: '/api/notes?attackId=anonymous_api_notes_read&x=1', headers: { 'user-agent': 'aleph-judge/1.0', cookie: 'sb-access=SECRETCOOKIE', authorization: 'Bearer SECRETTOKEN' } });
  assert.ok(!('ua' in h.rows[0]) && !('qs' in h.rows[0]) && !('hdrs' in h.rows[0]));
  assert.ok(!JSON.stringify(h.rows).match(/aleph-judge|attackId=|SECRETCOOKIE|SECRETTOKEN/u));
}));
