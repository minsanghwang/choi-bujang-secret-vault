import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ACCESS_COOKIE } from '../src/auth-service.mjs';
import { DEVICE_COOKIE, sha256 } from '../src/device-gate.mjs';
import { handleCollection, handleItem, handleNoticeCollection } from '../src/notes-service.mjs';

const A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const NOTE = '11111111-1111-4111-8111-111111111111';
const HANDLE = 'H'.repeat(43);
const verify = async authorization => ({ 'Bearer a.a.a': { kind: 'student', userId: A }, 'Bearer b.b.b': { kind: 'student', userId: B } })[authorization] ?? null;
const session = (token = 'a.a.a') => `${ACCESS_COOKIE}=${token}; ${DEVICE_COOKIE}=${HANDLE}`;

async function withEnv(fn) {
  const names = ['SUPABASE_URL', 'SUPABASE_SECRET_KEY'];
  const saved = Object.fromEntries(names.map(n => [n, process.env[n]]));
  Object.assign(process.env, { SUPABASE_URL: 'https://abc.supabase.co', SUPABASE_SECRET_KEY: 'fake-test-key-not-real-0123456789' });
  try { return await fn(); } finally { for (const n of names) { if (saved[n] === undefined) delete process.env[n]; else process.env[n] = saved[n]; } }
}
// 기기 표와 자료 표를 가진 가짜 서버. 자료 표를 읽거나 쓴 횟수를 셉니다.
function world(devices) {
  const w = { devices, noteCalls: 0, deviceCalls: 0, failDevices: false };
  w.fetch = async url => {
    const u = new URL(url);
    const table = u.pathname.split('/').pop();
    if (table === 'defense_devices') {
      w.deviceCalls += 1;
      if (w.failDevices) return new Response('{}', { status: 500 });
      const rows = w.devices.filter(row => [...u.searchParams].filter(([k]) => !['select', 'limit'].includes(k))
        .every(([k, v]) => String(row[k]) === v.replace(/^eq\./u, '')));
      return new Response(JSON.stringify(rows.map(({ id }) => ({ id }))), { status: 200 });
    }
    w.noteCalls += 1;
    return new Response(JSON.stringify([]), { status: 200 });
  };
  return w;
}
const row = (status, owner = A, handle = HANDLE) => ({ id: 'dddddddd-dddd-4ddd-8ddd-000000000001', owner_id: owner, handle_sha256: sha256(handle), status });
async function call(handler, w, request) {
  const out = { headers: new Map() };
  await handler({ query: {}, ...request }, { setHeader: (k, v) => out.headers.set(k.toLowerCase(), v),
    status: code => { out.status = code; return { json: data => { out.body = data; } }; } }, { verify, fetch: w.fetch });
  return out;
}

test('서버가 승인한 기기 쿠키가 있는 브라우저 로그인만 자료 API를 통과한다', () => withEnv(async () => {
  const w = world([row('approved')]);
  const ok = await call(handleCollection, w, { method: 'GET', headers: { cookie: session() } });
  assert.equal(ok.status, 200);
  assert.equal(w.noteCalls, 1);
}));

test('승인 전·해제·기기 쿠키 없음·남의 기기 쿠키·모양이 틀린 쿠키는 서버가 403으로 막고 자료 표를 읽지도 않는다', () => withEnv(async () => {
  const cases = {
    '대기(pending)': { devices: [row('pending')], cookie: session() },
    '해제(revoked)': { devices: [row('revoked')], cookie: session() },
    '등록된 기기 없음': { devices: [], cookie: session() },
    '기기 쿠키 없음': { devices: [row('approved')], cookie: `${ACCESS_COOKIE}=a.a.a` },
    '다른 사용자의 승인된 기기': { devices: [row('approved', B)], cookie: session() },
    '모양이 틀린 기기 쿠키': { devices: [row('approved')], cookie: `${ACCESS_COOKIE}=a.a.a; ${DEVICE_COOKIE}=short` },
  };
  for (const [name, { devices, cookie }] of Object.entries(cases)) {
    const w = world(devices);
    for (const [handler, request] of [[handleCollection, { method: 'GET' }], [handleCollection, { method: 'POST', body: { title: 't', body: 'b' } }],
      [handleItem, { method: 'GET', query: { id: NOTE } }], [handleItem, { method: 'DELETE', query: { id: NOTE } }], [handleNoticeCollection, { method: 'GET' }]]) {
      const res = await call(handler, w, { ...request, headers: { cookie } });
      assert.equal(res.status, 403, `${name} ${request.method}`);
      assert.deepEqual(res.body, { error: 'DEVICE_NOT_APPROVED' });
      assert.equal(res.headers.get('x-deny-reason'), 'device_not_approved');
    }
    assert.equal(w.noteCalls, 0, name);                       // 자료 표를 읽거나 쓰지 않음
  }
}));

test('기기 승인 여부를 확인하지 못하면 승인으로 가정하지 않고 503으로 닫는다', () => withEnv(async () => {
  const w = world([row('approved')]);
  w.failDevices = true;
  const res = await call(handleCollection, w, { method: 'GET', headers: { cookie: session() } });
  assert.equal(res.status, 503);
  assert.equal(w.noteCalls, 0);
}));

test('Authorization 헤더로 직접 오는 요청은 기존 로그인·소유자 확인 그대로이고 기기 확인을 더하지 않는다', () => withEnv(async () => {
  const w = world([]);
  const res = await call(handleCollection, w, { method: 'GET', headers: { authorization: 'Bearer a.a.a' } });
  assert.equal(res.status, 200);
  assert.equal(w.deviceCalls, 0);
  assert.equal((await call(handleCollection, w, { method: 'GET', headers: {} })).status, 401);        // 로그인 없음은 그대로 401
  assert.equal((await call(handleCollection, w, { method: 'GET', headers: { authorization: 'Bearer x.y.z' } })).status, 401);
}));

test('로그인이 없으면 기기 표를 읽기 전에 401이다', () => withEnv(async () => {
  const w = world([row('approved')]);
  const res = await call(handleCollection, w, { method: 'GET', headers: { cookie: `${DEVICE_COOKIE}=${HANDLE}` } });
  assert.equal(res.status, 401);
  assert.equal(w.deviceCalls, 0);
}));
