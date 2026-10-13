import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const PUBLIC = new URL('../public/', import.meta.url);
const read = name => readFile(new URL(name, PUBLIC), 'utf8');

test('manifest에는 앱 이름·시작 주소·표시 방식·아이콘이 있고, 설치가 기기 승인이 아니라고 적혀 있다', async () => {
  const manifest = JSON.parse(await read('manifest.webmanifest'));
  assert.equal(manifest.name, 'BYTE BACK 자료실');
  assert.ok(manifest.short_name && manifest.lang === 'ko');
  assert.deepEqual([manifest.start_url, manifest.scope, manifest.display], ['/', '/', 'standalone']);
  assert.match(manifest.description, /기기 승인 여부는 서버가 정하며, 설치 여부는 판단에 쓰지 않습니다/u);
  const sizes = manifest.icons.map(icon => icon.sizes);
  assert.ok(sizes.includes('192x192') && sizes.includes('512x512'));
  for (const icon of manifest.icons) {
    const bytes = await readFile(new URL(icon.src.slice(1), PUBLIC));
    assert.equal(bytes.subarray(1, 4).toString(), 'PNG');
  }
});

test('공개 파일 어디에도 브라우저 저장소·쿠키 읽기가 없고, 기기 키·토큰 값도 없다', async () => {
  for (const name of ['index.html', 'sw.js', 'offline.html', 'manifest.webmanifest']) {
    const text = await read(name);
    assert.doesNotMatch(text, /localStorage|sessionStorage|indexedDB|document\.cookie|crypto\.subtle|PRIVATE KEY|eyJ[A-Za-z0-9_-]{20,}/u, name);
  }
  const html = await read('index.html');
  assert.match(html, /<link rel="manifest" href="\/manifest\.webmanifest">/u);
  assert.match(html, /자료실을 여는 조건은 서버가 확인한 승인 결과뿐이며, 설치 여부는 판단에 쓰지 않습니다/u);
});

test('서비스 워커는 /api와 /aleph.json을 가로채지 않고 보관하지 않으며, 정적 파일만 보관한다', async () => {
  const sw = await read('sw.js');
  assert.match(sw, /url\.pathname\.startsWith\('\/api\/'\)[^\n]*return;/u);
  assert.match(sw, /\/aleph\.json/u);
  assert.doesNotMatch(sw, /cache\.put|cache\.add\(|\.put\(/u);                                      // 응답을 임의로 보관하지 않음
  const files = sw.match(/STATIC_FILES = \[([^\]]*)\]/u)[1];
  assert.doesNotMatch(files, /\/api|index|data\.json|aleph/u);
  assert.match(sw, /request\.method !== 'GET'\) return;/u);
});

// ---- 화면 코드를 가짜 DOM으로 실제 실행해 승인 전에는 자료를 요청·표시하지 않는지 확인합니다 ----
async function runPage({ device }) {   // device(options)는 GET·POST 요청마다 서버 응답을 흉내 냅니다.
  const html = await read('index.html');
  const script = html.match(/<script type="module">([\s\S]*?)<\/script>/u)[1];
  const elements = new Map();
  const element = () => ({ hidden: false, disabled: false, textContent: '', value: '', children: [], handlers: {}, addEventListener(type, fn) { this.handlers[type] = fn; }, reset() {},
    replaceChildren(...items) { this.children = items; }, appendChild() {}, set className(v) {}, setAttribute() {} });
  const document = { getElementById: id => { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); }, createElement: element };
  const calls = [];
  const reply = (status, data) => ({ status, json: async () => data });
  const fetchStub = async (path, options = {}) => {
    calls.push(`${options.method ?? 'GET'} ${path}`);
    if (path === '/api/auth/session') return reply(200, { email: 'tester@example.test' });
    if (path === '/api/device') return device(options);
    if (path === '/api/notes') return reply(200, [{ id: '1', title: '가상 메모', body: '내용' }]);
    return reply(404, { error: 'NOT_FOUND' });
  };
  const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor;
  await new AsyncFunction('document', 'fetch', 'navigator', 'window', script)(
    document, fetchStub, { onLine: true }, { addEventListener() {} });
  return { els: elements, calls };
}

for (const state of ['none', 'pending', 'revoked']) {
  test(`승인 전(${state})에는 자료 영역이 숨겨지고 /api/notes를 부르지 않는다`, async () => {
    const page = await runPage({ device: () => ({ status: 200, json: async () => ({ state, deviceId: 'dddddddd-dddd-4ddd-8ddd-000000000001' }) }) });
    assert.equal(page.els.get('vault').hidden, true);
    assert.equal(page.els.get('device').hidden, false);
    assert.deepEqual(page.calls.filter(call => call.includes('/api/notes')), []);
    assert.equal(page.els.get('notes').children.length, 0);
  });
}

test('서버가 approved라고 답한 기기에서만 기존 자료실이 열리고 /api/notes를 부른다', async () => {
  const page = await runPage({ device: () => ({ status: 200, json: async () => ({ state: 'approved' }) }) });
  assert.equal(page.els.get('vault').hidden, false);
  assert.deepEqual(page.calls.filter(call => call.includes('/api/notes')), ['GET /api/notes']);
  assert.equal(page.els.get('device-state').textContent, '승인된 기기');
});

test('승인 상태를 확인하지 못하거나 모르는 값이면 자료를 열지 않는다', async () => {
  for (const device of [() => ({ status: 502, json: async () => ({ error: 'DEVICE_UPSTREAM_ERROR' }) }),
    () => ({ status: 200, json: async () => ({ state: 'trusted' }) }), () => ({ status: 200, json: async () => ({}) })]) {
    const page = await runPage({ device });
    assert.equal(page.els.get('vault').hidden, true);
    assert.deepEqual(page.calls.filter(call => call.includes('/api/notes')), []);
  }
});

test('승인 요청 버튼은 요청만 보내고, 요청 응답이 approved여도 서버에 다시 물어본 결과가 아니면 자료실을 열지 않는다', async () => {
  const answers = { post: { status: 201, json: async () => ({ state: 'approved', deviceId: 'x' }) },   // 요청 응답이 approved라고 해도
    get: { status: 200, json: async () => ({ state: 'pending', deviceId: 'x' }) } };                      // 서버가 이번에 알려 주는 상태는 pending
  const page = await runPage({ device: options => (options?.method === 'POST' ? answers.post : answers.get) });
  await page.els.get('device-request').handlers.click();
  assert.equal(page.els.get('vault').hidden, true);
  assert.deepEqual(page.calls.filter(call => call.includes('/api/notes')), []);
  assert.deepEqual(page.calls.filter(call => call.includes('/api/device')), ['GET /api/device', 'POST /api/device', 'GET /api/device']);
  answers.get = { status: 200, json: async () => ({ state: 'approved' }) };                              // 서버가 승인했다고 답하면 그때만 열림
  await page.els.get('device-refresh').handlers.click();
  assert.equal(page.els.get('vault').hidden, false);
  assert.deepEqual(page.calls.filter(call => call.includes('/api/notes')), ['GET /api/notes']);
});

test('화면 코드에서 자료실(vault)을 여는 곳은 서버 확인 결과를 받은 checkDevice 한 곳뿐이다', async () => {
  const html = await read('index.html');
  assert.equal((html.match(/\$\('vault'\)\.hidden = false/gu) ?? []).length, 1);
  assert.match(html, /if \(info\?\.state === 'approved'\) \{ \$\('vault'\)\.hidden = false; await load\(\); \}/u);
  assert.doesNotMatch(html, /beforeinstallprompt|appinstalled|display-mode/u);                           // 설치 이벤트를 열림 조건에 쓰지 않음
});
