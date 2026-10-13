import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { DEVICE_COOKIE, handleDevice } from '../src/device-service.mjs';

const A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const verify = async authorization => ({ 'Bearer a.a.a': { kind: 'student', userId: A }, 'Bearer b.b.b': { kind: 'student', userId: B } })[authorization] ?? null;
const asA = { authorization: 'Bearer a.a.a' };
const asB = { authorization: 'Bearer b.b.b' };

async function call(request, deps) {
  const out = { headers: new Map() };
  const response = { setHeader: (k, v) => out.headers.set(k.toLowerCase(), v),
    status: code => { out.status = code; return { json: data => { out.body = data; } }; } };
  await handleDevice(request, response, deps);
  return out;
}
async function withEnv(fn) {
  const names = ['SUPABASE_URL', 'SUPABASE_SECRET_KEY', 'INSTRUCTOR_USER_IDS'];
  const saved = Object.fromEntries(names.map(n => [n, process.env[n]]));
  Object.assign(process.env, { SUPABASE_URL: 'https://abc.supabase.co', SUPABASE_SECRET_KEY: 'fake-test-key-not-real-0123456789' });
  try { return await fn(); } finally { for (const n of names) { if (saved[n] === undefined) delete process.env[n]; else process.env[n] = saved[n]; } }
}
// defense_devices 하나만 있는 메모리 DB. eq·in 필터와 limit만 해석합니다.
function fakeDb(rows = []) {
  const db = { rows, calls: [] };
  let seq = 0;
  db.fetch = async (url, init) => {
    const u = new URL(url);
    db.calls.push({ table: u.pathname.split('/').pop(), method: init.method });
    const reply = (status, body) => new Response(JSON.stringify(body), { status });
    if (init.method === 'POST') {
      const row = { id: `dddddddd-dddd-4ddd-8ddd-${String(++seq).padStart(12, '0')}`, requested_at: '2026-10-13T00:00:00Z', decided_at: null, ...JSON.parse(init.body) };
      rows.push(row);
      return reply(201, [row]);
    }
    const match = row => [...u.searchParams].filter(([k]) => !['select', 'limit'].includes(k)).every(([k, v]) => {
      if (v.startsWith('in.(')) return v.slice(4, -1).split(',').includes(String(row[k]));
      return String(row[k] ?? '') === v.replace(/^eq\./u, '');
    });
    return reply(200, rows.filter(match).slice(0, Number(u.searchParams.get('limit') ?? Infinity)).map(r => ({ ...r })));
  };
  return db;
}
const get = (db, headers) => call({ method: 'GET', headers }, { verify, fetch: db.fetch });
const post = (db, headers, body) => call({ method: 'POST', headers, body }, { verify, fetch: db.fetch });
const cookieOf = res => { const raw = res.headers.get('set-cookie'); return raw ? raw.split(';')[0] : null; };
const sha = text => createHash('sha256').update(text).digest('hex');

test('로그인 없이는 조회·요청 모두 401이고 DB를 읽지도 쓰지도 않는다', () => withEnv(async () => {
  const db = fakeDb();
  assert.equal((await get(db, {})).status, 401);
  assert.equal((await post(db, {}, {})).status, 401);
  assert.equal((await get(db, { authorization: 'Bearer x.y.z' })).status, 401);
  assert.equal(db.calls.length, 0);
}));

test('요청 전에는 none이고, 요청하면 pending이 되며 쿠키에는 읽을 수 없는 핸들만 담긴다', () => withEnv(async () => {
  const db = fakeDb();
  assert.deepEqual((await get(db, asA)).body, { state: 'none' });
  const res = await post(db, asA, {});
  assert.equal(res.status, 201);
  assert.equal(res.body.state, 'pending');
  const raw = res.headers.get('set-cookie');
  assert.match(raw, new RegExp(`^${DEVICE_COOKIE}=[A-Za-z0-9_-]{43};`, 'u'));
  assert.match(raw, /HttpOnly/u); assert.match(raw, /Secure/u); assert.match(raw, /SameSite=Strict/u); assert.match(raw, /Path=\//u);
  const handle = raw.split(';')[0].split('=')[1];
  assert.ok(!JSON.stringify(res.body).includes(handle));                       // 응답 본문에 핸들이 없음
  assert.equal(db.rows.length, 1);
  assert.deepEqual([db.rows[0].status, db.rows[0].owner_id, db.rows[0].handle_sha256], ['pending', A, sha(handle)]);   // DB에는 지문만
  assert.ok(!JSON.stringify(db.rows).includes(handle));
  assert.equal(res.headers.get('cache-control'), 'no-store');
}));

test('승인 상태는 DB 값만 정하고, 같은 기기로 다시 요청해도 새 행이 생기지 않는다', () => withEnv(async () => {
  const db = fakeDb();
  const cookie = cookieOf(await post(db, asA, {}));
  const mine = { ...asA, cookie };
  assert.equal((await get(db, mine)).body.state, 'pending');
  assert.equal((await post(db, mine, {})).body.state, 'pending');
  assert.equal(db.rows.length, 1);
  db.rows[0].status = 'approved';                                              // 운영 측이 DB에서 승인
  assert.equal((await get(db, mine)).body.state, 'approved');
  db.rows[0].status = 'revoked';
  assert.equal((await get(db, mine)).body.state, 'revoked');
  assert.equal((await post(db, mine, {})).body.state, 'revoked');              // 해제된 기기는 요청으로 되살아나지 않음
  assert.equal(db.rows.length, 1);
}));

test('본문·쿼리·헤더로는 승인되지 않는다', () => withEnv(async () => {
  const db = fakeDb();
  for (const body of [{ status: 'approved' }, { approved: true }, { role: 'instructor' }, { deviceId: 'x' }, '{"status":"approved"}', 'not json', [1]]) {
    const res = await post(db, asA, body);
    assert.equal(res.status, 400, JSON.stringify(body));
  }
  assert.equal(db.rows.length, 0);
  const res = await call({ method: 'GET', headers: { ...asA, 'x-device-approved': 'true' }, query: { status: 'approved' }, url: '/api/device?status=approved' }, { verify, fetch: db.fetch });
  assert.deepEqual(res.body, { state: 'none' });
  assert.ok(db.rows.every(row => row.status === 'pending'));
}));

test('다른 사용자의 쿠키나 모양이 틀린 쿠키는 인정하지 않는다', () => withEnv(async () => {
  const db = fakeDb();
  const cookie = cookieOf(await post(db, asA, {}));
  db.rows[0].status = 'approved';
  assert.deepEqual((await get(db, { ...asB, cookie })).body, { state: 'none' });                 // B가 A의 쿠키를 써도 none
  assert.equal((await get(db, { ...asA, cookie })).body.state, 'approved');
  assert.deepEqual((await get(db, { ...asA, cookie: `${DEVICE_COOKIE}=short` })).body, { state: 'none' });
  assert.deepEqual((await get(db, { ...asA, cookie: `${DEVICE_COOKIE}=${'A'.repeat(43)}` })).body, { state: 'none' });
  const other = await post(db, { ...asB, cookie }, {});                                           // B는 자기 행을 따로 만들 뿐
  assert.equal(other.status, 201);
  assert.equal(other.body.state, 'pending');
  assert.equal(db.rows.length, 2);
}));

test('한 사용자의 대기·승인 기기는 5대까지다', () => withEnv(async () => {
  const db = fakeDb();
  for (let i = 0; i < 5; i += 1) assert.equal((await post(db, asA, {})).status, 201);
  const res = await post(db, asA, {});
  assert.equal(res.status, 429);
  assert.equal(res.headers.get('x-deny-reason'), 'device_limit');
  assert.equal(db.rows.length, 5);
  assert.equal((await post(db, asB, {})).status, 201);                          // 다른 사용자는 영향 없음
}));

test('GET·POST 외의 메서드는 405이고 DB 오류는 502로 닫힌다', () => withEnv(async () => {
  const db = fakeDb();
  for (const method of ['PUT', 'DELETE', 'PATCH']) assert.equal((await call({ method, headers: asA }, { verify, fetch: db.fetch })).status, 405);
  assert.equal(db.calls.length, 0);
  const broken = async () => new Response('{}', { status: 500 });
  assert.equal((await call({ method: 'POST', headers: asA, body: {} }, { verify, fetch: broken })).status, 502);
  const down = async () => { throw new Error('network'); };
  assert.equal((await call({ method: 'GET', headers: { ...asA, cookie: `${DEVICE_COOKIE}=${'a'.repeat(43)}` } }, { verify, fetch: down })).status, 502);
}));
