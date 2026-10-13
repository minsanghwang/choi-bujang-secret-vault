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

async function send(url, authorization, extraHeaders = {}) {
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: { ...(authorization ? { Authorization: authorization } : {}), ...extraHeaders } });
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
  if (![5, 6, 7, 8, 9].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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

  // 5단계 가점: 첫 화면 코드에 Supabase 공개 키(sb_publishable_… 또는 anon 키)가 보이면 안 됩니다.
  const page = await fetch(app, { redirect: 'error', signal: AbortSignal.timeout(10000) });
  const pageText = await page.text();
  const keyVisible = /sb_publishable_[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}/u.test(pageText);

  // 5단계: 원본 자료 저장소를 공개 키(anon)만으로 직접 불러 봅니다. 메모가 보이면 안 됩니다.
  let direct = null;
  const publicKey = config.database?.publishableKey;
  if (typeof config.originalApiUrl === 'string' && config.originalApiUrl.startsWith('https://')
      && typeof publicKey === 'string' && publicKey) {
    direct = await send(config.originalApiUrl, null, { apikey: publicKey });
  }
  const directObserved = direct === null
    ? '미실행: originalApiUrl 또는 공개 키가 설정에 없어 직접 요청을 보내지 않음'
    : `${noteCount(direct.data) === 0 ? '메모가 보이지 않음' : '메모가 보임'} (HTTP ${direct.status}, 메모 ${noteCount(direct.data)}건)`;

  return [
    { attackId: 'static_data_json_read', expected: '비로그인으로 /data.json을 열어도 메모가 없어야 함',
      observed: staticLeak ? `비로그인 /data.json에서 메모가 보임 (HTTP ${staticData.status})`
        : `비로그인 /data.json에서 메모가 보이지 않음 (HTTP ${staticData.status})` },
    { attackId: 'anonymous_api_notes_read', expected: '로그인 없이 /api/notes를 부르면 401 또는 403과 JSON 오류 문구',
      observed: `비로그인 /api/notes ${describe(anonymous, denied(anonymous))}` },
    { attackId: 'forged_token_notes_read', expected: '서명 없는 가짜 토큰으로 /api/notes를 부르면 401 또는 403과 JSON 오류 문구',
      observed: `가짜 토큰 /api/notes ${describe(forged, denied(forged))}` },
    { attackId: 'public_key_in_screen_code', expected: '첫 화면 코드에 Supabase 공개 키(sb_publishable_… 또는 anon 키)가 없음',
      observed: `${keyVisible ? '첫 화면에 공개 키가 보임' : '첫 화면에 공개 키가 보이지 않음'} (HTTP ${page.status})` },
    { attackId: 'direct_original_api_anon_read', expected: '공개 키(anon)로 원본 자료 저장소를 직접 불러도 메모가 보이지 않음(401·403 또는 빈 목록)',
      observed: directObserved },
    { attackId: 'login_a_note_crud', expected: '정상 A 로그인 뒤 자기 가상 메모 읽기·추가·수정·삭제',
      observed: '미실행: 이 점검은 로그인 계정 정보 없이 실행되어 A 로그인 요청을 보내지 않음' },
    { attackId: 'b_reads_a_note', expected: 'B 로그인으로 A의 메모 번호를 요청하면 403(또는 404)이고 A의 메모가 보이지 않음',
      observed: '미실행: 이 점검은 B 로그인 계정 정보 없이 실행되어 B 요청을 보내지 않음' },
    { attackId: 'b_changes_a_note', expected: 'B 로그인으로 A의 메모를 수정·삭제하거나 소유자를 바꾸려 하면 거부됨',
      observed: '미실행: 이 점검은 B 로그인 계정 정보 없이 실행되어 B 요청을 보내지 않음' },
    // 6단계: 미등록 기기 공격은 심판이 판정기에 가상 요청으로 보냅니다. 학생 점검은 이 요청을 보내지 않습니다.
    ...(config.step >= 6 ? [{ attackId: 'unregistered_device_request',
      expected: '등록되지 않은 기기의 요청은 판정기가 deny·device_not_registered로 거부함',
      observed: '미실행: 이 요청은 심판이 보내며, 학생 점검은 npm run decider:test의 가상 요청 연습만 함' }] : []),
    // 7단계: 이상 접속 추가 확인과 새 로그인 뒤 재판정은 엔진·심판이 보내는 사건이라 학생 점검은 보내지 않습니다.
    ...(config.step >= 7 ? [{ attackId: 'unusual_access_step_up',
      expected: '평소와 다른 시각·처음 보는 네트워크·많은 읽기가 함께이면 추가 확인(step_up), 정상 사건은 허용',
      observed: '미실행: 이 사건은 심판이 보내며, 학생 점검은 npm run decider:test의 가상 요청 연습만 함. 실제 재로그인 전 자료 차단은 엔진 계약 환경에서만 실측' }] : []),
    // 8단계: 구역 점검은 로그인 계정이 필요해 학생 점검이 보내지 않습니다. 비로그인 요청만 보냅니다.
    ...(config.step >= 8 ? [{ attackId: 'cross_zone_direct_api',
      expected: 'B가 A의 메모를, 일반 학생이 강사 공지 수정을 직접 API로 요청하면 403이고 자료가 나오지 않음',
      observed: '미실행: 이 점검은 A·B·강사 로그인 계정 정보 없이 실행되어 구역 간 요청을 보내지 않음. 로컬 시험은 가짜 DB로만 확인함' }] : []),
    // 9단계: 탐지 사건과 회수 집행은 운영 엔진·심판이 가상 사건으로 보냅니다. 학생 점검은 사건을 보내지 않습니다.
    ...(config.step >= 9 ? [{ attackId: 'doppelganger_burst_revocation',
      expected: '같은 사용자의 조회가 10분 안에 120건을 넘는 복합 의심 사건만 propose_revocation(burst_read)을 내고, 정상 기기는 유지됨',
      observed: '미실행: 이 사건은 심판이 보내며, 학생 점검은 npm run detect:test의 가상 사건 연습만 함. 실제 사건 전달·접속 회수·걸린 시간은 엔진 계약 환경에서만 실측' }] : []),
  ];
}
