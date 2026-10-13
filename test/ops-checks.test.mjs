import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RESULT, buildChecks, runChecks, summarize, toMarkdown } from '../src/ops-checks.mjs';

const config = { publicAppUrl: 'https://app.example.test', sampleMarker: 'SAMPLE_NOTE_1',
  identityProvider: { issuer: 'https://p.supabase.co/auth/v1', audience: 'authenticated' }, database: { url: 'https://p.supabase.co', publishableKey: 'pk-public' }, originalApiUrl: 'https://p.supabase.co/rest/v1/defense_notes' };
const jwt = sub => `h.${Buffer.from(JSON.stringify({ sub })).toString('base64url')}.s`;
const A = jwt('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
const B = jwt('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');

// 서버를 흉내 내는 가짜 fetch: 요청마다 응답하고 요청 ID를 기록 표에 쌓습니다.
function fakeServer({ leakNotice = false } = {}) {
  const log = new Map();
  const calls = [];
  const fetch = async (url, options = {}) => {
    const u = new URL(url);
    const headers = options.headers ?? {};
    const token = (headers.Authorization ?? '').replace('Bearer ', '');
    const who = token === A ? 'A' : token === B ? 'B' : token ? 'forged' : 'none';
    const requestId = headers['X-Request-Id'];
    calls.push(`${options.method ?? 'GET'} ${u.pathname}${u.search ? '?…' : ''} as ${who}`);
    const reply = (status, data, record = true) => {
      if (record && requestId) log.set(requestId, status);          // 실제 서버처럼 /api/ops도 기록함
      return new Response(data === null ? null : JSON.stringify(data), { status, headers: { 'content-type': 'application/json', 'x-request-id': requestId ?? 'none' } });
    };
    if (u.pathname === '/data.json') return reply(404, { error: 'NOT_FOUND' }, false);
    if (u.host === 'p.supabase.co') return reply(headers.apikey === 'pk-public' ? 200 : 401, [], false);   // 공개 키 직접 조회: 빈 목록
    if (u.pathname === '/api/ops') {
      if (who !== 'A') return reply(401, { error: 'LOGIN_REQUIRED' });
      const id = u.searchParams.get('requestId');
      if (id) return reply(200, { schema: 'aleph.ops.record.v1', record: log.has(id) ? { requestId: id, status: log.get(id) } : null });
      return reply(200, { schema: 'aleph.ops.v1' });
    }
    if (who === 'none' || who === 'forged') return reply(401, { error: 'LOGIN_REQUIRED' });
    if (u.pathname === '/api/notes' && options.method === 'POST') return reply(201, { id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' });
    if (u.pathname === '/api/notes') return reply(200, []);
    if (u.pathname.startsWith('/api/notes/')) {
      if (who === 'B') return reply(leakNotice ? 200 : 403, leakNotice ? { title: 'x' } : { error: 'FORBIDDEN' });
      return reply(options.method === 'DELETE' ? 204 : 200, options.method === 'DELETE' ? null : { id: 'c' });
    }
    if (u.pathname === '/api/notices') return reply(200, [{ id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', title: '공지', body: '내용' }]);
    if (u.pathname.startsWith('/api/notices/')) return reply(403, { error: 'FORBIDDEN' });
    if (u.pathname === '/api/restore') return reply(403, { error: 'NOT_OWNER' });
    if (u.pathname === '/api/device' && options.method === 'POST') return reply(options.body && options.body !== '{}' ? 400 : 201, options.body && options.body !== '{}' ? { error: 'INVALID_DEVICE_REQUEST' } : { state: 'pending' });
    if (u.pathname === '/api/device') return reply(200, { state: 'none' });
    return reply(404, { error: 'NOT_FOUND' });
  };
  return { fetch, calls, log };
}
let n = 0;
const uuid = () => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`;
const now = () => new Date('2026-10-13T00:00:00Z');

test('계정이 모두 있으면 요청마다 요청 ID·확인 시각·기대·실제 결과가 한 줄에 남고 서버 기록과 일치한다', async () => {
  const server = fakeServer();
  const rows = await runChecks({ config, tokens: { A, B }, fetch: server.fetch, uuid, now });
  const ran = rows.filter(row => row.result !== RESULT.notRun);
  assert.ok(ran.length >= 18);
  for (const row of ran) {
    assert.match(row.requestId, /^[0-9a-f-]{36}$/u);
    assert.equal(row.checkedAt, '2026-10-13T00:00:00.000Z');
    assert.match(row.actual, /^HTTP \d{3}/u);
    assert.equal(row.result, RESULT.match, row.name);
  }
  const logged = ran.filter(row => !['해당 없음'].includes(row.serverRecord));
  assert.ok(logged.length >= 16 && logged.every(row => row.serverRecord === '일치'));     // /api/ops 두 줄도 서버 기록과 대조됨
  assert.deepEqual(ran.filter(row => row.serverRecord === '해당 없음').map(row => row.name).sort(), ['공개 키로 원본 저장소 직접 조회', '정적 /data.json 공개']);   // 우리 서버를 거치지 않는 두 줄만 기록 대상이 아님
  assert.ok(rows.some(row => row.kind === '정상') && rows.some(row => row.kind === '금지'));       // 허용과 거부 모두 측정 결과로 남음
});

test('판정기·탐지·회수·41종 줄은 항상 미실행이고 통과로 표시되지 않는다', async () => {
  const rows = await runChecks({ config, tokens: { A, B }, fetch: fakeServer().fetch, uuid, now });
  for (const stage of [6, 7, 9]) assert.equal(rows.find(row => row.stage === stage).result, RESULT.notRun);
  const last = rows.find(row => row.name === '41종 총공세');
  assert.equal(last.result, RESULT.notRun);
  assert.equal(last.requestId, null);
  assert.match(toMarkdown(rows), /41종 총공세: 미실행/u);
});

test('계정 환경변수가 없으면 로그인 필요한 줄은 요청을 보내지 않고 미실행 이유를 적는다', async () => {
  const server = fakeServer();
  const rows = await runChecks({ config, tokens: {}, fetch: server.fetch, uuid, now });
  assert.ok(server.calls.every(call => /as (none|forged)$/u.test(call)));
  const a = rows.find(row => row.name === 'A 로그인 메모 목록');
  assert.equal(a.result, RESULT.notRun);
  assert.match(a.note, /A 로그인 환경변수가 없음/u);
  assert.equal(rows.find(row => row.name === '비로그인 메모 목록').serverRecord, '확인 못함');   // 기록 조회에는 A 토큰이 필요
});

test('금지 요청이 막히지 않으면 불일치로 적는다(통과로 바꾸지 않음)', async () => {
  const rows = await runChecks({ config, tokens: { A, B }, fetch: fakeServer({ leakNotice: true }).fetch, uuid, now });
  assert.equal(rows.find(row => row.name === 'B가 A의 메모 읽기').result, RESULT.mismatch);
  assert.ok(summarize(rows).mismatch >= 1);
});

test('요청을 보내지 못하면 미실행이고, 표와 파일에는 토큰·비밀번호·메모 내용이 없다', async () => {
  const failing = async () => { throw new Error('network'); };
  const rows = await runChecks({ config, tokens: { A, B }, fetch: failing, uuid, now });
  assert.ok(rows.every(row => row.result === RESULT.notRun));
  const server = fakeServer();
  const full = await runChecks({ config, tokens: { A, B }, fetch: server.fetch, uuid, now });
  const dump = JSON.stringify(full) + toMarkdown(full);
  assert.doesNotMatch(dump, /Bearer|eyJ|password|ops-table 점검용 가상 메모|자동 생성/u);
  assert.ok(!dump.includes(A) && !dump.includes(B));
  assert.ok(buildChecks(config).length >= 18);
});

test('5단계 공개 키 직접 조회·비로그인 복원·본문으로 승인 상태를 보내는 기기 요청도 실제로 보내 결과를 남긴다', async () => {
  const server = fakeServer();
  const rows = await runChecks({ config, tokens: { A, B }, fetch: server.fetch, uuid, now });
  const direct = rows.find(row => row.name === '공개 키로 원본 저장소 직접 조회');
  assert.deepEqual([direct.result, direct.actual, direct.serverRecord], [RESULT.match, 'HTTP 200', '해당 없음']);   // 빈 목록 = 메모가 보이지 않음
  assert.ok(server.calls.includes('GET /rest/v1/defense_notes as none'));
  assert.deepEqual([rows.find(row => row.name === '비로그인 복원 요청').result, rows.find(row => row.name === '비로그인 복원 요청').actual], [RESULT.match, 'HTTP 401 LOGIN_REQUIRED']);
  const device = rows.find(row => row.name === 'A가 본문으로 승인 상태를 보내는 기기 요청');
  assert.deepEqual([device.result, device.actual], [RESULT.match, 'HTTP 400 INVALID_DEVICE_REQUEST']);
  const noKey = await runChecks({ config: { ...config, originalApiUrl: undefined }, tokens: { A, B }, fetch: fakeServer().fetch, uuid, now });
  assert.match(noKey.find(row => row.name === '공개 키로 원본 저장소 직접 조회').note, /originalApiUrl 또는 공개 키가 설정에 없음/u);
});
