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

// 이 점검이 실제로 보낸 요청에는 fetch의 alephEvidence(점검 이름)와 헤더 X-Attack-Id·X-Request-Id를 붙입니다.
// 서버 기록(요청 ID)과 이 결과를 같은 요청으로 대조할 수 있고, 요청을 보내지 않은 점검에는 붙일 것이 없어 미실행으로 남습니다.
const uuid4 = () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/gu, c => { const r = Math.floor(Math.random() * 16); return (c === 'x' ? r : (r & 3) | 8).toString(16); });
const sentIds = {};
// 헤더 이름은 소문자로 붙입니다(HTTP 헤더는 대소문자를 가리지 않지만, 기록 도구가 객체의 키를 그대로 읽는 경우를 위해).
const tagged = attackId => { const requestId = uuid4(); sentIds[attackId] = requestId; return { 'x-attack-id': attackId, 'x-aleph-attack-id': attackId, 'x-request-id': requestId }; };

// alephEvidence의 형식이 문서에 없습니다. 문자열과 {attackId, requestId}는 이미 시험했으므로, 이번에는 키가 하나뿐인 객체 두 가지를 보냅니다.
// 격리 환경은 요청을 24번까지만 허용하므로 점검마다 읽기 전용(GET) 요청을 두 번(총 16번)만 보내고, 결과에는 마지막 요청의 ID를 적습니다.
const evidenceVariants = attackId => [{ attack_id: attackId }, { attackId }];
async function send(url, authorization, extraHeaders = {}, attackId = null) {
  let response;
  for (const evidence of attackId ? evidenceVariants(attackId) : [null]) {
    const tags = attackId ? tagged(attackId) : {};
    response = await fetch(url, { redirect: 'error', signal: timeout(10000), ...(evidence ? { alephEvidence: evidence } : {}),
      headers: { ...(authorization ? { Authorization: authorization } : {}), ...extraHeaders, ...tags } });
  }
  const contentType = response.headers.get('content-type') ?? '';
  let data = null;
  if (/json/iu.test(contentType)) {
    try { data = await response.json(); } catch { /* JSON이 아닌 본문 */ }
  }
  return { status: response.status, json: data !== null, data };
}
const noteCount = data => (Array.isArray(data) ? data.length
  : Array.isArray(data?.notes) ? data.notes.length : 0);
// Node 전용 전역(Buffer 등)이 없는 환경에서도 돌도록 base64url을 직접 만듭니다. 입력은 ASCII뿐입니다(JSON 머리·값, 가짜 서명 표시).
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
export function base64url(text) {
  let out = '';
  for (let i = 0; i < text.length; i += 3) {
    const a = text.charCodeAt(i) & 255;
    const b = i + 1 < text.length ? text.charCodeAt(i + 1) & 255 : null;
    const c = i + 2 < text.length ? text.charCodeAt(i + 2) & 255 : null;
    out += B64URL[a >> 2] + B64URL[((a & 3) << 4) | ((b ?? 0) >> 4)];
    if (b !== null) out += B64URL[((b & 15) << 2) | ((c ?? 0) >> 6)];
    if (c !== null) out += B64URL[c & 63];
  }
  return out;
}
const b64 = value => base64url(JSON.stringify(value));
// 시간 제한 신호는 지원하는 환경에서만 붙입니다(없으면 제한 없이 요청).
const timeout = ms => (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function' ? AbortSignal.timeout(ms) : undefined);

// 서명 없이 직접 만든 가짜 토큰입니다. 학생 발급자·일반 사용자 모양만 흉내 냅니다.
function forgedToken(identityProvider) {
  const claims = { iss: identityProvider.issuer, aud: identityProvider.audience, role: 'authenticated',
    sub: '00000000-0000-4000-8000-000000000000', exp: Math.floor(Date.now() / 1000) + 3600 };
  return `Bearer ${b64({ alg: 'ES256', typ: 'JWT' })}.${b64(claims)}.${base64url('forged')}`;
}

export async function runAttackChecks(config) {
  if (![5, 6, 7, 8, 9, 10, 11, 12].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  for (const key of Object.keys(sentIds)) delete sentIds[key];
  const app = appUrl(config);
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  if (!config.identityProvider?.issuer) throw new Error('aleph.config.json의 identityProvider를 먼저 적어 주세요.');

  const staticData = await send(new URL('/data.json', app), null, {}, 'static_data_json_read');
  const staticLeak = staticData.data !== null
    && (staticData.data.sampleMarker === config.sampleMarker || noteCount(staticData.data) > 0);
  const anonymous = await send(new URL('/api/notes', app), null, {}, 'anonymous_api_notes_read');
  const forged = await send(new URL('/api/notes', app), forgedToken(config.identityProvider), {}, 'forged_token_notes_read');
  const denied = result => [401, 403].includes(result.status) && result.json && noteCount(result.data) === 0
    && typeof result.data?.error === 'string';
  const describe = (result, ok) => `${ok ? '거부됨' : '거부되지 않음'} (HTTP ${result.status}, ${result.json ? 'JSON' : 'JSON 아님'}, 메모 ${noteCount(result.data)}건)`;

  // 11단계: 로그인 없이 기기 승인 상태를 물으면 거부되어야 하고, 앱 설정(manifest)은 공개되어야 합니다. 이 두 요청만 실제로 보냅니다.
  const deviceAnonymous = config.step >= 11 ? await send(new URL('/api/device', app), null, {}, 'device_status_without_login') : null;
  const manifest = config.step >= 11 ? await send(new URL('/manifest.webmanifest', app), null, {}, 'manifest_public') : null;

  // 12단계: 로그인 없이 작전실 요약(/api/ops)을 부르면 거부되어야 합니다. 이 요청만 실제로 보냅니다.
  const opsAnonymous = config.step >= 12 ? await send(new URL('/api/ops', app), null, {}, 'ops_summary_without_login') : null;

  // 5단계 가점: 첫 화면 코드에 Supabase 공개 키(sb_publishable_… 또는 anon 키)가 보이면 안 됩니다.
  let page;
  for (const evidence of evidenceVariants('public_key_in_screen_code')) {
    page = await fetch(app, { redirect: 'error', signal: timeout(10000), alephEvidence: evidence, headers: tagged('public_key_in_screen_code') });
  }
  // 임시 관찰(원인을 찾으면 지웁니다): 점검 환경의 전역 이름 끝부분과 환경변수 "이름"(값은 읽지 않음)을 서버 기록의 쿼리로 확인합니다.
  if (config.step >= 12) {
    const tail = (label, text, count) => { const out = []; for (let i = 0; i < count; i += 1) { const end = text.length - i * 110; if (end > 0) out.push([`${label}${i}`, text.slice(Math.max(0, end - 110), end)]); } return out; };
    let probe = [];
    try {
      probe = [...tail('t', Object.getOwnPropertyNames(globalThis).join(','), 3),
        ...tail('e', typeof process !== 'undefined' && process.env ? Object.keys(process.env).join(',') : 'noenv', 3)];
    } catch { /* 관찰 실패 */ }
    for (const [name, text] of probe) {
      try { await fetch(new URL(`/api/device?c=${name}&f=${base64url(text)}`, app), { redirect: 'error', signal: timeout(10000) }); } catch { /* 관찰 실패는 점검 결과에 영향을 주지 않습니다. */ }
    }
  }
  const pageText = await page.text();
  const keyVisible = /sb_publishable_[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}/u.test(pageText);

  // 5단계: 원본 자료 저장소를 공개 키(anon)만으로 직접 불러 봅니다. 메모가 보이면 안 됩니다.
  let direct = null;
  const publicKey = config.database?.publishableKey;
  if (typeof config.originalApiUrl === 'string' && config.originalApiUrl.startsWith('https://')
      && typeof publicKey === 'string' && publicKey) {
    direct = await send(config.originalApiUrl, null, { apikey: publicKey }, 'direct_original_api_anon_read');
  }
  const directObserved = direct === null
    ? '미실행: originalApiUrl 또는 공개 키가 설정에 없어 직접 요청을 보내지 않음'
    : `${noteCount(direct.data) === 0 ? '메모가 보이지 않음' : '메모가 보임'} (HTTP ${direct.status}, 메모 ${noteCount(direct.data)}건)`;

  const results = [
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
    // 10단계: 복원과 복구 뒤 재확인은 사본 표와 로그인 계정이 필요해 학생 점검이 보내지 않습니다.
    ...(config.step >= 10 ? [{ attackId: 'restore_one_note_from_backup',
      expected: '시험 계정 B의 메모 한 건만 비공개 사본에서 복원되고 ID·소유자·내용 해시가 사본과 같음, 다른 메모와 감사 기록은 그대로',
      observed: '미실행: 이 점검은 B 로그인 계정과 사본 SQL 적용 없이 실행되어 POST /api/restore를 보내지 않음. 로컬 시험은 가짜 DB로만 확인함' },
    { attackId: 'post_restore_regression',
      expected: '복구 뒤 1~9단계의 정상 요청은 허용되고 B의 A 자료 요청 같은 금지 요청은 다시 거부됨',
      observed: '미실행: README의 복구 뒤 재확인 순서를 아직 실행하지 않음' }] : []),
    // 11단계: 승인 요청·승인 뒤 화면 열림은 로그인 계정과 운영 측 승인이 필요해 학생 점검이 보내지 않습니다.
    ...(config.step >= 11 ? [{ attackId: 'device_status_without_login',
      expected: '로그인 없이 /api/device를 부르면 401 또는 403과 JSON 오류 문구이고 승인 상태가 나오지 않음',
      observed: `비로그인 /api/device ${describe(deviceAnonymous, denied(deviceAnonymous) && deviceAnonymous.data?.state === undefined)}` },
    { attackId: 'manifest_public',
      expected: '/manifest.webmanifest가 공개되고 앱 이름이 있음(자료실을 여는 조건은 서버가 확인한 승인 결과뿐)',
      observed: `${manifest.status === 200 && manifest.json && typeof manifest.data?.name === 'string' ? '앱 설정이 공개됨' : '앱 설정을 확인하지 못함'} (HTTP ${manifest.status}, ${manifest.json ? 'JSON' : 'JSON 아님'})` },
    { attackId: 'device_approval_gate',
      expected: '승인 전 기기에는 자료가 없고, 서버가 승인한 기기에서만 기존 화면이 열림',
      observed: '미실행: 이 점검은 로그인 계정과 운영 측 승인 없이 실행되어 POST /api/device를 보내지 않음. 로컬 시험은 가짜 DB와 가짜 화면으로만 확인함' }] : []),
    // 12단계: 작전실 요약은 로그인과 승인된 기기가 필요합니다. 41종 총공세는 심판이 실행하며 학생 점검은 보내지 않습니다.
    ...(config.step >= 12 ? [{ attackId: 'ops_summary_without_login',
      expected: '로그인 없이 /api/ops를 부르면 401 또는 403과 JSON 오류 문구이고 요약 수치가 나오지 않음',
      observed: `비로그인 /api/ops ${describe(opsAnonymous, denied(opsAnonymous) && opsAnonymous.data?.schema === undefined)}` },
    { attackId: 'full_41_attack_run',
      expected: '41종 공격 방어는 심판이 실행하며, 학생 점검은 그 결과를 만들거나 대신 표시하지 않음',
      observed: '미실행: 41종 총공세는 심판이 보내며, 학생 점검과 작전실은 결과를 갖고 있지 않음. 1~11단계 정상·금지 요청의 실측은 npm run ops:table(로그인 계정 환경변수 필요)로만 남김' }] : []),
  ];
  // 실제로 보낸 점검에만 그 요청 ID를 덧붙입니다(미실행 점검에는 붙지 않음).
  return results.map(item => (sentIds[item.attackId] ? { ...item, observed: `${item.observed} [요청 ID ${sentIds[item.attackId]}]` } : item));
}
