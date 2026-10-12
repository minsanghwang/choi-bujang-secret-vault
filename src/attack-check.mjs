// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
function appUrl(config) {
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  return app;
}

async function send(url, authorization) {
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: authorization ? { Authorization: authorization } : {} });
  const contentType = response.headers.get('content-type') ?? '';
  let data = null;
  if (/json/iu.test(contentType)) {
    try { data = await response.json(); } catch { /* JSON이 아닌 본문 */ }
  }
  return { status: response.status, json: data !== null, data };
}
const noteCount = data => (Array.isArray(data) ? data.length
  : Array.isArray(data?.notes) ? data.notes.length : 0);
const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');

// 서명 없이 직접 만든 가짜 토큰입니다. 학생 발급자·일반 사용자 모양만 흉내 냅니다.
function forgedToken(identityProvider) {
  const claims = { iss: identityProvider.issuer, aud: identityProvider.audience, role: 'authenticated',
    sub: '00000000-0000-4000-8000-000000000000', exp: Math.floor(Date.now() / 1000) + 3600 };
  return `Bearer ${b64({ alg: 'ES256', typ: 'JWT' })}.${b64(claims)}.${Buffer.from('forged').toString('base64url')}`;
}

export async function runAttackChecks(config) {
  if (config.step !== 3) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  const app = appUrl(config);
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  if (!config.identityProvider?.issuer) throw new Error('aleph.config.json의 identityProvider를 먼저 적어 주세요.');

  const staticData = await send(new URL('/data.json', app));
  const staticLeak = staticData.data !== null
    && (staticData.data.sampleMarker === config.sampleMarker || noteCount(staticData.data) > 0);
  const anonymous = await send(new URL('/api/notes', app));
  const forged = await send(new URL('/api/notes', app), forgedToken(config.identityProvider));
  const denied = result => [401, 403].includes(result.status) && result.json && noteCount(result.data) === 0
    && typeof result.data?.error === 'string';
  const describe = (result, ok) => `${ok ? '거부됨' : '거부되지 않음'} (HTTP ${result.status}, ${result.json ? 'JSON' : 'JSON 아님'}, 메모 ${noteCount(result.data)}건)`;

  return [
    { attackId: 'static_data_json_read', expected: '비로그인으로 /data.json을 열어도 메모가 없어야 함',
      observed: staticLeak ? `비로그인 /data.json에서 메모가 보임 (HTTP ${staticData.status})`
        : `비로그인 /data.json에서 메모가 보이지 않음 (HTTP ${staticData.status})` },
    { attackId: 'anonymous_api_notes_read', expected: '로그인 없이 /api/notes를 부르면 401 또는 403과 JSON 오류 문구',
      observed: `비로그인 /api/notes ${describe(anonymous, denied(anonymous))}` },
    { attackId: 'forged_token_notes_read', expected: '서명 없는 가짜 토큰으로 /api/notes를 부르면 401 또는 403과 JSON 오류 문구',
      observed: `가짜 토큰 /api/notes ${describe(forged, denied(forged))}` },
    { attackId: 'login_a_note_crud', expected: '정상 A 로그인 뒤 가상 메모 추가·수정·삭제',
      observed: '미실행: 이 점검은 로그인 계정 정보 없이 실행되어 A 로그인 요청을 보내지 않음' },
  ];
}
