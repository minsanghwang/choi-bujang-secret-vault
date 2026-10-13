import assert from 'node:assert/strict';
import { test } from 'node:test';
import { handleItem, handleNoticeItem } from '../src/notes-service.mjs';
import { authorize, instructorIds, resourceId, zoneOf } from '../src/zones.mjs';

const A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const TEACHER = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const NOTE = '11111111-1111-4111-8111-111111111111';
const NOTICE = '55555555-5555-4555-8555-555555555555';
const verify = async authorization => ({ 'Bearer a.b.c': { kind: 'student', userId: A },
  'Bearer d.e.f': { kind: 'student', userId: B }, 'Bearer t.t.t': { kind: 'student', userId: TEACHER } })[authorization] ?? null;
const asA = { authorization: 'Bearer a.b.c' };
const asB = { authorization: 'Bearer d.e.f' };
const asTeacher = { authorization: 'Bearer t.t.t' };

async function call(handler, { method = 'GET', headers = {}, body, query } = {}, deps) {
  const out = { headers: new Map() };
  const response = {
    setHeader: (key, value) => out.headers.set(key.toLowerCase(), value),
    status: code => { out.status = code; return { json: data => { out.body = data; }, end: () => { out.ended = true; } }; },
  };
  await handler({ method, headers, body, query }, response, deps);
  return out;
}
async function withEnv(extra, fn) {
  const names = ['SUPABASE_URL', 'SUPABASE_SECRET_KEY', 'INSTRUCTOR_USER_IDS'];
  const saved = Object.fromEntries(names.map(name => [name, process.env[name]]));
  Object.assign(process.env, { SUPABASE_URL: 'https://abc.supabase.co', SUPABASE_SECRET_KEY: 'fake-test-key-not-real-0123456789' });
  delete process.env.INSTRUCTOR_USER_IDS;
  Object.assign(process.env, extra);
  try { return await fn(); } finally {
    for (const name of names) { if (saved[name] === undefined) delete process.env[name]; else process.env[name] = saved[name]; }
  }
}
// id·owner_id·zone의 eq 필터를 해석하는 메모리 DB. zoneColumn=false이면 옛 DB처럼 zone을 고르는 요청을 400으로 거부합니다.
function memoryDb(rows, { zoneColumn = true } = {}) {
  const db = { rows, calls: [] };
  db.fetch = async (url, init) => {
    const u = new URL(url);
    db.calls.push({ method: init.method, url: u, body: init.body ? JSON.parse(init.body) : undefined });
    const reply = (status, body) => new Response(JSON.stringify(body), { status });
    if (!zoneColumn && (u.searchParams.get('select') ?? '').includes('zone')) return reply(400, { code: '42703' });
    const match = row => ['id', 'owner_id', 'zone'].every(k => !u.searchParams.has(k)
      || (row[k] ?? (k === 'zone' ? 'note' : undefined)) === u.searchParams.get(k).replace(/^eq\./u, ''));
    const hit = db.rows.filter(match);
    if (init.method === 'PATCH') hit.forEach(r => Object.assign(r, JSON.parse(init.body)));
    if (init.method === 'DELETE') db.rows = db.rows.filter(r => !hit.includes(r));
    return reply(200, hit.map(r => ({ ...r })));
  };
  return db;
}
const rows = () => [
  { id: NOTE, owner_id: A, zone: 'note', title: 'A 메모', content: 'a' },
  { id: NOTICE, owner_id: TEACHER, zone: 'notice', title: '공지', content: 'n' },
];
const note = (db, headers, method = 'GET', body, id = NOTE) => call(handleItem, { method, headers, query: { id }, body }, { verify, fetch: db.fetch });
const notice = (db, headers, method = 'GET', body, id = NOTICE) => call(handleNoticeItem, { method, headers, query: { id }, body }, { verify, fetch: db.fetch });

test('자원 ID는 구역마다 다르게 표시되고 요청마다 서버가 구별한다', async () => {
  await withEnv({}, async () => {
    const db = memoryDb(rows());
    assert.equal((await note(db, asA)).headers.get('x-resource-id'), `note:${NOTE}`);
    assert.equal((await notice(db, asA)).headers.get('x-resource-id'), `notice:${NOTICE}`);
    assert.notEqual(resourceId('note', NOTE), resourceId('notice', NOTE));
  });
});

test('A 자기 메모는 유지되고, B의 A 메모 요청은 쓰기 없이 403이다', async () => {
  await withEnv({}, async () => {
    const db = memoryDb(rows());
    assert.deepEqual((await note(db, asA)).body, { id: NOTE, title: 'A 메모', body: 'a' });
    assert.equal((await note(db, asA, 'PUT', { title: '새 제목', body: 'x' })).status, 200);
    for (const [method, body] of [['GET'], ['PUT', { title: 'x', body: 'y', role: 'instructor' }], ['DELETE']]) {
      const res = await note(db, { ...asB, 'x-role': 'instructor' }, method, body);
      assert.equal(res.status, 403, method);
      assert.deepEqual(res.body, { error: 'FORBIDDEN' });
      assert.equal(res.headers.get('x-deny-reason'), 'owner_mismatch');
    }
    assert.equal(db.calls.filter(c => c.method === 'DELETE').length, 0);
    assert.equal(db.rows.find(r => r.id === NOTE).title, '새 제목');
  });
});

test('일반 학생의 공지 수정은 거부되고, 본문·헤더의 role은 믿지 않는다', async () => {
  await withEnv({}, async () => {
    const db = memoryDb(rows());
    assert.equal((await notice(db, asB)).status, 200);   // 읽기는 로그인한 사용자 모두
    for (const headers of [asA, asB, { ...asA, 'x-role': 'instructor' }]) {
      const res = await notice(db, headers, 'PUT', { title: '변조', body: 'x', role: 'instructor', owner_id: A });
      assert.equal(res.status, 403);
      assert.equal(res.headers.get('x-deny-reason'), 'instructor_required');
    }
    assert.equal(db.calls.filter(c => c.method === 'PATCH').length, 0);
    assert.equal(db.rows.find(r => r.id === NOTICE).title, '공지');
  });
});

test('서버에 강사로 저장된 계정만 공지를 고치고, 소유자·구역은 바뀌지 않는다', async () => {
  await withEnv({ INSTRUCTOR_USER_IDS: ` ${TEACHER.toUpperCase()} ,not-a-uuid` }, async () => {
    const db = memoryDb(rows());
    const res = await notice(db, asTeacher, 'PUT', { title: '새 공지', body: '내용', zone: 'note', owner_id: A });
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, { id: NOTICE, title: '새 공지', body: '내용' });
    const patch = db.calls.find(c => c.method === 'PATCH');
    assert.deepEqual(patch.body, { title: '새 공지', content: '내용' });
    assert.equal(patch.url.searchParams.get('zone'), 'eq.notice');
    assert.equal(db.rows.find(r => r.id === NOTICE).owner_id, TEACHER);
    assert.equal((await notice(db, asA, 'PUT', { title: 'x', body: 'y' })).status, 403);
  });
});

test('다른 구역의 주소로 요청하면 강사여도 거부하고, 추가·삭제 방식은 공지 API에 없다', async () => {
  await withEnv({ INSTRUCTOR_USER_IDS: TEACHER }, async () => {
    const db = memoryDb(rows());
    for (const headers of [asA, asTeacher]) {
      const viaNotes = await note(db, headers, 'GET', undefined, NOTICE);
      assert.equal(viaNotes.status, 403);
      assert.equal(viaNotes.headers.get('x-deny-reason'), 'wrong_zone');
    }
    const viaNotices = await notice(db, asA, 'GET', undefined, NOTE);
    assert.equal(viaNotices.status, 403);
    assert.equal(viaNotices.headers.get('x-deny-reason'), 'wrong_zone');
    for (const method of ['POST', 'DELETE']) assert.equal((await notice(db, asTeacher, method)).status, 405);
    assert.equal(db.rows.length, 2);
  });
});

test('알 수 없는 구역 값과 옛 DB(구역 열 없음)를 안전하게 처리한다', async () => {
  await withEnv({}, async () => {
    const odd = memoryDb([{ id: NOTE, owner_id: A, zone: 'vip', title: 't', content: 'c' }]);
    const res = await note(odd, asA);
    assert.equal(res.status, 403);
    assert.equal(res.headers.get('x-deny-reason'), 'unknown_zone');
    const legacy = memoryDb([{ id: NOTE, owner_id: A, title: 'A 메모', content: 'a' }], { zoneColumn: false });
    assert.equal((await note(legacy, asA)).status, 200);          // SQL 적용 전에도 본인 메모는 그대로
    assert.equal((await note(legacy, asB)).status, 403);
    assert.equal((await notice(legacy, asA, 'GET', undefined, NOTE)).status, 403);
  });
});

test('zones.mjs: 판단 함수는 입력한 값만으로 결정한다', () => {
  assert.equal(zoneOf({}), 'note');
  assert.equal(zoneOf({ zone: 'notice' }), 'notice');
  assert.equal(zoneOf({ zone: '__proto__' }), null);
  assert.equal(instructorIds({ INSTRUCTOR_USER_IDS: '' }).size, 0);
  const row = { id: NOTE, owner_id: A, zone: 'note' };
  assert.equal(authorize({ route: 'note', action: 'read', row, userId: A, env: {} }).allow, true);
  assert.equal(authorize({ route: 'note', action: 'read', row: { ...row, owner_id: null }, userId: A, env: {} }).reason, 'owner_missing');
});
