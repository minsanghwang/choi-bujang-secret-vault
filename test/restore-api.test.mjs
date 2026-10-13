import assert from 'node:assert/strict';
import { test } from 'node:test';
import { handleRestore, noteHash } from '../src/restore-service.mjs';

const A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const TEACHER = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const B_NOTE = '22222222-2222-4222-8222-222222222222';
const A_NOTE = '11111111-1111-4111-8111-111111111111';
const NOTICE = '55555555-5555-4555-8555-555555555555';
const SECRET_TEXT = '비공개 가상 메모 본문';
const verify = async authorization => ({ 'Bearer a.a.a': { kind: 'student', userId: A }, 'Bearer b.b.b': { kind: 'student', userId: B },
  'Bearer t.t.t': { kind: 'student', userId: TEACHER } })[authorization] ?? null;
const asA = { authorization: 'Bearer a.a.a' };
const asB = { authorization: 'Bearer b.b.b' };
const asTeacher = { authorization: 'Bearer t.t.t' };
const GOOD = noteHash('B 원래 제목', SECRET_TEXT);

async function call(request, deps) {
  const out = { headers: new Map() };
  const response = { setHeader: (k, v) => out.headers.set(k.toLowerCase(), v),
    status: code => { out.status = code; return { json: data => { out.body = data; } }; } };
  await handleRestore(request, response, deps);
  return out;
}
async function withEnv(extra, fn) {
  const names = ['SUPABASE_URL', 'SUPABASE_SECRET_KEY', 'INSTRUCTOR_USER_IDS'];
  const saved = Object.fromEntries(names.map(n => [n, process.env[n]]));
  Object.assign(process.env, { SUPABASE_URL: 'https://abc.supabase.co', SUPABASE_SECRET_KEY: 'fake-test-key-not-real-0123456789' });
  delete process.env.INSTRUCTOR_USER_IDS;
  Object.assign(process.env, extra);
  try { return await fn(); } finally { for (const n of names) { if (saved[n] === undefined) delete process.env[n]; else process.env[n] = saved[n]; } }
}
// 표 이름별 메모리 DB. eq 필터·limit만 해석하고, 감사 표는 PATCH·DELETE를 거부합니다(덧붙이기만).
function fakeDb({ notes, backups, failAudit = false }) {
  const db = { tables: { defense_notes: notes, defense_notes_backup: backups, defense_restore_audit: [] }, calls: [] };
  db.fetch = async (url, init) => {
    const u = new URL(url);
    const table = u.pathname.split('/').pop();
    const method = init.method;
    db.calls.push({ table, method });
    const reply = (status, body) => new Response(JSON.stringify(body), { status });
    const rows = db.tables[table];
    if (table === 'defense_restore_audit' && method !== 'POST' && method !== 'GET') return reply(500, {});
    if (table === 'defense_restore_audit' && failAudit) return reply(500, {});
    if (method === 'POST') { const row = { ...JSON.parse(init.body) }; rows.push(row); return reply(201, [row]); }
    const match = row => [...u.searchParams].filter(([k]) => !['select', 'limit', 'order'].includes(k))
      .every(([k, v]) => String(row[k] ?? '').toLowerCase() === v.replace(/^eq\./u, '').toLowerCase());
    const hit = rows.filter(match);
    if (u.searchParams.get('order') === 'backed_up_at.asc') hit.sort((x, y) => String(x.backed_up_at ?? '').localeCompare(String(y.backed_up_at ?? '')));
    if (method === 'PATCH') hit.forEach(r => Object.assign(r, JSON.parse(init.body)));
    if (method === 'DELETE') db.tables[table] = rows.filter(r => !hit.includes(r));
    return reply(200, hit.slice(0, Number(u.searchParams.get('limit') ?? Infinity)).map(r => ({ ...r })));
  };
  return db;
}
const backupRow = (extra = {}) => ({ note_id: B_NOTE, owner_id: B, position: 3, title: 'B 원래 제목', content: SECRET_TEXT,
  note_created_at: '2026-09-01T00:00:00Z', content_sha256: GOOD, ...extra });
const world = (extra = {}) => fakeDb({
  notes: [{ id: A_NOTE, owner_id: A, zone: 'note', title: 'A 메모', content: 'a 내용' },
    { id: NOTICE, owner_id: null, zone: 'notice', title: '공지', content: '공지 내용' },
    { id: B_NOTE, owner_id: B, zone: 'note', title: '침해로 바뀐 제목', content: '침해로 바뀐 내용' }],
  backups: [backupRow(), { ...backupRow({ note_id: A_NOTE, owner_id: A, title: 'A 메모', content: 'a 내용' }), content_sha256: noteHash('A 메모', 'a 내용') }], ...extra });
const real = db => db.tables.defense_restore_audit.filter(r => r.outcome !== 'trace');
const post = (db, headers, body, method = 'POST') => call({ method, headers, body }, { verify, fetch: db.fetch });
const want = (extra = {}) => ({ id: B_NOTE, ownerId: B, contentSha256: GOOD, dryRun: false, ...extra });

test('B가 자기 메모 한 건을 복원하면 ID·소유자·내용 해시가 사본과 같고 다른 메모는 그대로다', () => withEnv({}, async () => {
  const db = world();
  const others = JSON.stringify(db.tables.defense_notes.filter(r => r.id !== B_NOTE));
  const res = await post(db, asB, want());
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { applied: true, restored: true, created: false, id: B_NOTE, ownerId: B, contentSha256: GOOD });
  const live = db.tables.defense_notes.find(r => r.id === B_NOTE);
  assert.equal(noteHash(live.title, live.content), GOOD);                      // 내용 해시가 사본과 같음
  assert.equal(live.owner_id, B);                                                // 소유자가 사본과 같음
  assert.equal(JSON.stringify(db.tables.defense_notes.filter(r => r.id !== B_NOTE)), others);   // A 메모·공지는 그대로
  assert.equal(db.tables.defense_notes_backup.length, 2);                        // 사본은 그대로
  assert.deepEqual(real(db).map(r => r.outcome), ['started', 'restored']);
  assert.ok(!JSON.stringify(res.body).includes(SECRET_TEXT));                    // 응답에 메모 본문이 없음
  assert.ok(db.calls.every(c => !(c.method === 'DELETE')));                      // 어떤 행도 지우지 않음
}));

test('메모가 지워진 상태에서는 사본의 ID·소유자·위치로 한 건을 다시 만든다', () => withEnv({}, async () => {
  const db = world();
  db.tables.defense_notes = db.tables.defense_notes.filter(r => r.id !== B_NOTE);
  const res = await post(db, asB, want());
  assert.equal(res.status, 200);
  assert.equal(res.body.created, true);
  const live = db.tables.defense_notes.find(r => r.id === B_NOTE);
  assert.deepEqual([live.owner_id, live.position, noteHash(live.title, live.content)], [B, 3, GOOD]);
  assert.equal(db.tables.defense_notes.length, 3);
}));

test('미리보기는 쓰지 않고 복원할 사본 버전과 바뀔 항목, 실제 복원에 보낼 확인값만 보여 준다', () => withEnv({}, async () => {
  const db = world();
  db.tables.defense_notes_backup[0].backup_id = 'cccccccc-0000-4000-8000-000000000001';
  db.tables.defense_notes_backup[0].backed_up_at = '2026-10-13T05:14:49Z';
  const before = JSON.stringify(db.tables.defense_notes);
  for (const body of [want({ dryRun: true }), { id: B_NOTE }, want({ dryRun: undefined })]) {
    const res = await post(db, asB, body);
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, { applied: false, dryRun: true, id: B_NOTE, ownerId: B, contentSha256: GOOD,
      backup: { id: 'cccccccc-0000-4000-8000-000000000001', takenAt: '2026-10-13T05:14:49Z', verified: true },
      liveExists: true, liveMatchesCopy: false, changes: { create: false, title: true, content: true }, willWrite: true,
      confirm: { dryRun: false, ownerId: B, contentSha256: GOOD } });
    assert.ok(!JSON.stringify(res.body).includes(SECRET_TEXT));
  }
  assert.equal(JSON.stringify(db.tables.defense_notes), before);
  assert.ok(db.calls.every(c => c.table !== 'defense_notes' || c.method === 'GET'));
  // 이미 사본과 같으면 바뀔 항목이 없다고 알려 준다.
  const same = world();
  Object.assign(same.tables.defense_notes.find(r => r.id === B_NOTE), { title: 'B 원래 제목', content: SECRET_TEXT });
  assert.deepEqual((await post(same, asB, { id: B_NOTE })).body.changes, { create: false, title: false, content: false });
}));

test('실제 복원에는 소유자와 내용 해시 확인값이 모두 있어야 하고, 없으면 쓰지 않는다', () => withEnv({}, async () => {
  const db = world();
  const before = JSON.stringify(db.tables.defense_notes);
  for (const body of [{ id: B_NOTE, dryRun: false }, { id: B_NOTE, ownerId: B, dryRun: false }, { id: B_NOTE, contentSha256: GOOD, dryRun: false }]) {
    const res = await post(db, asB, body);
    assert.equal(res.status, 400, JSON.stringify(body));
    assert.equal(res.headers.get('x-deny-reason'), 'confirmation_required');
  }
  assert.equal(JSON.stringify(db.tables.defense_notes), before);
  assert.equal(real(db).length, 0);
}));

test('다른 사람(A)이 B의 메모를 복원하려 하거나 강사가 아니면 사본을 읽기 전에 403이다', () => withEnv({}, async () => {
  const db = world();
  const res = await post(db, asA, want());
  assert.equal(res.status, 403);
  assert.equal(res.headers.get('x-deny-reason'), 'not_owner');
  assert.ok(!db.calls.some(c => c.table === 'defense_notes_backup'));
  assert.deepEqual(real(db).map(r => r.outcome), ['denied']);
  // A가 본문에 자기를 소유자로 적고 B의 번호를 요청해도 사본의 소유자와 달라 거부된다.
  const forged = await post(db, asA, want({ ownerId: A }));
  assert.equal(forged.status, 404);                                              // A의 이름으로 찾으면 B의 사본은 보이지 않음
  assert.equal(db.tables.defense_notes.find(r => r.id === B_NOTE).title, '침해로 바뀐 제목');
}));

test('서버에 등록된 강사는 다른 사람의 메모 한 건을 복원할 수 있다', () => withEnv({ INSTRUCTOR_USER_IDS: TEACHER }, async () => {
  const db = world();
  assert.equal((await post(db, asTeacher, want())).status, 200);
  assert.equal(real(db)[0].actor, TEACHER);
}));

test('ID·소유자·내용 해시 중 하나라도 사본과 다르면 쓰지 않는다', () => withEnv({}, async () => {
  for (const [extra, status] of [[{ contentSha256: noteHash('x', 'y') }, 404], [{ id: A_NOTE }, 404]]) {
    const db = world();
    const before = JSON.stringify(db.tables.defense_notes);
    const res = await post(db, asB, want(extra));
    assert.equal(res.status, status, JSON.stringify(extra));
    assert.equal(JSON.stringify(db.tables.defense_notes), before);
  }
  // 사본 행이 바뀌어(내용 변조) 저장된 해시가 내용과 맞지 않으면 409.
  const tampered = world();
  tampered.tables.defense_notes_backup[0].content = '바뀐 사본';
  const res = await post(tampered, asB, want());
  assert.equal(res.status, 409);
  assert.equal(tampered.tables.defense_notes.find(r => r.id === B_NOTE).title, '침해로 바뀐 제목');
  // 사본의 소유자가 요청과 다르면 409.
  const otherOwner = world();
  otherOwner.tables.defense_notes_backup[0].owner_id = A;
  assert.equal((await post(otherOwner, asB, want())).status, 404);
}));

test('공지 번호나 소유자가 바뀐 자리는 덮어쓰지 않는다', () => withEnv({}, async () => {
  const toNotice = world();
  toNotice.tables.defense_notes.find(r => r.id === B_NOTE).zone = 'notice';
  const res = await post(toNotice, asB, want());
  assert.equal(res.headers.get('x-deny-reason'), 'wrong_zone');
  const moved = world();
  moved.tables.defense_notes.find(r => r.id === B_NOTE).owner_id = A;
  const second = await post(moved, asB, want());
  assert.equal(second.headers.get('x-deny-reason'), 'owner_change');
  assert.equal(moved.tables.defense_notes.find(r => r.id === B_NOTE).owner_id, A);
}));

test('본문 형식이 틀리거나 로그인이 없거나 POST가 아니면 쓰지 않는다', () => withEnv({}, async () => {
  const db = world();
  for (const body of [undefined, 'x', {}, want({ id: 'nope' }), want({ contentSha256: 'abc' }), want({ role: 'instructor' }), want({ content: '직접 내용' }), want({ dryRun: 'yes' })]) {
    assert.equal((await post(db, asB, body)).status, 400, JSON.stringify(body));
  }
  assert.equal((await post(db, {}, want())).status, 401);
  assert.equal((await post(db, asB, want(), 'GET')).status, 405);
  assert.ok(db.calls.every(c => c.table === 'defense_restore_audit' && c.method === 'POST'));   // 사본·메모 표는 읽지도 쓰지도 않음
}));

test('감사 기록을 남기지 못하면 쓰지 않고, 감사 표에는 지우기·고치기 요청을 보내지 않는다', () => withEnv({}, async () => {
  const db = world({ failAudit: true });
  const before = JSON.stringify(db.tables.defense_notes);
  assert.equal((await post(db, asB, want())).status, 503);
  assert.equal(JSON.stringify(db.tables.defense_notes), before);
  const ok = world();
  await post(ok, asB, want());
  assert.ok(ok.calls.filter(c => c.table === 'defense_restore_audit').every(c => c.method === 'POST'));
}));

test('미리보기에서 받은 확인값을 그대로 보내면 한 건이 복원되고, noteId도 같은 뜻으로 받는다', () => withEnv({}, async () => {
  const db = world();
  const preview = await post(db, asB, { id: B_NOTE });
  const done = await post(db, asB, { id: B_NOTE, ...preview.body.confirm });
  assert.equal(done.status, 200);
  assert.deepEqual(done.body, { applied: true, restored: true, created: false, id: B_NOTE, ownerId: B, contentSha256: GOOD });
  const live = db.tables.defense_notes.find(r => r.id === B_NOTE);
  assert.equal(noteHash(live.title, live.content), GOOD);
  const alias = world();
  assert.equal((await post(alias, asB, { noteId: B_NOTE })).status, 200);
  assert.equal((await post(alias, asB, { id: B_NOTE, noteId: A_NOTE })).status, 400);   // 서로 다른 번호는 거부
}));

test('id만 보낸 요청도 남의 메모는 복원하지 못하고 쓰기가 없다', () => withEnv({}, async () => {
  const db = world();
  const before = JSON.stringify(db.tables.defense_notes);
  const res = await post(db, asA, { id: B_NOTE });                // A가 B의 번호만 보냄 → A의 이름으로 찾으므로 사본 없음
  assert.equal(res.status, 404);
  assert.equal(JSON.stringify(db.tables.defense_notes), before);
  const asOwnerClaim = await post(db, asA, { id: B_NOTE, ownerId: B });
  assert.equal(asOwnerClaim.status, 403);                          // 본문의 소유자 값으로 권한이 생기지 않음
  assert.equal(JSON.stringify(db.tables.defense_notes), before);
}));

test('해시를 생략하면 그 메모의 가장 오래된(침해 전) 사본을 쓰고, 해시를 주면 그 사본만 쓴다', () => withEnv({}, async () => {
  const later = noteHash('B 나중 제목', '나중 내용');
  const db = world();
  db.tables.defense_notes_backup[0].backed_up_at = '2026-10-01T00:00:00Z';
  db.tables.defense_notes_backup.push(backupRow({ title: 'B 나중 제목', content: '나중 내용', content_sha256: later, backed_up_at: '2026-10-02T00:00:00Z' }));
  const oldest = await post(db, asB, { id: B_NOTE });
  assert.equal(oldest.body.contentSha256, GOOD);
  const picked = world();
  picked.tables.defense_notes_backup[0].backed_up_at = '2026-10-01T00:00:00Z';
  picked.tables.defense_notes_backup.push(backupRow({ title: 'B 나중 제목', content: '나중 내용', content_sha256: later, backed_up_at: '2026-10-02T00:00:00Z' }));
  assert.equal((await post(picked, asB, { id: B_NOTE, contentSha256: later })).body.contentSha256, later);
}));

test('사본 내용이 저장된 해시와 맞지 않으면 id만 보내도 쓰지 않는다', () => withEnv({}, async () => {
  const db = world();
  db.tables.defense_notes_backup[0].content = '바뀐 사본';
  const before = JSON.stringify(db.tables.defense_notes);
  const res = await post(db, asB, { id: B_NOTE });
  assert.equal(res.status, 409);
  assert.equal(res.headers.get('x-deny-reason'), 'backup_mismatch');
  assert.equal(JSON.stringify(db.tables.defense_notes), before);
}));

test('모든 요청은 값 없이 한 줄의 흔적(메서드·상태·인증 방식·본문 키 이름)만 남긴다', () => withEnv({}, async () => {
  const db = world();
  await post(db, asB, { id: B_NOTE, 비밀: 'x', contentSha256: GOOD });
  await post(db, {}, { noteId: B_NOTE });
  await post(db, asB, undefined, 'GET');
  const lines = db.tables.defense_restore_audit.filter(r => r.outcome === 'trace').map(r => r.reason);
  assert.deepEqual(lines, ['m=POST;s=400;a=bearer;k=id,contentSha256', 'm=POST;s=401;a=none;k=noteId', 'm=GET;s=405;a=bearer;k=none']);
  assert.ok(db.tables.defense_restore_audit.every(r => !JSON.stringify(r).includes(B) && !JSON.stringify(r).includes(SECRET_TEXT)));
}));

test('흔적은 응답을 보내기 전에 먼저 쓴다(응답 뒤에는 서버 함수가 멈출 수 있음)', () => withEnv({}, async () => {
  const db = world();
  const order = [];
  const inner = db.fetch;
  db.fetch = async (url, init) => { if (init.method === 'POST' && String(url).includes('defense_restore_audit') && JSON.parse(init.body).outcome === 'trace') order.push('trace'); return inner(url, init); };
  const response = { setHeader() {}, status: () => ({ json: () => order.push('response') }) };
  await handleRestore({ method: 'POST', headers: { authorization: 'Bearer b.b.b' }, body: { id: B_NOTE } }, response, { verify, fetch: db.fetch });
  assert.deepEqual(order.slice(-2), ['trace', 'response']);
}));
