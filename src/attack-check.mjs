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

async function anonymousJson(url) {
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(10000) });
  let data = null;
  if (response.ok) {
    try {
      data = await response.json();
    } catch {
      // A non-JSON response is not a note list.
    }
  }
  return { status: response.status, data };
}

export async function runAttackChecks(config) {
  if (config.step !== 2) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  const app = appUrl(config);
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  // 2단계 점검 1: 옛 공개 파일 /data.json에 메모가 남지 않아야 합니다.
  const staticData = await anonymousJson(new URL('/data.json', app));
  const staticLeak = staticData.data !== null
    && (staticData.data.sampleMarker === config.sampleMarker
      || (Array.isArray(staticData.data.notes) && staticData.data.notes.length > 0));
  // 2단계 점검 2: 서버 함수는 아직 로그인 확인이 없으므로 비로그인으로 불러집니다. 알려진 약점입니다.
  const api = await anonymousJson(new URL('/api/notes', app));
  const apiCount = Array.isArray(api.data?.notes) ? api.data.notes.length : 0;
  return [
    { attackId: 'static_data_json_read', expected: '비로그인으로 /data.json을 열어도 메모가 없어야 함',
      observed: staticLeak ? `비로그인 /data.json에서 메모가 보임 (HTTP ${staticData.status})`
        : `비로그인 /data.json에서 메모가 보이지 않음 (HTTP ${staticData.status})` },
    { attackId: 'anonymous_api_notes_read', expected: '2단계에서는 서버 함수가 아직 공개 주소라 메모가 보이는 것이 알려진 약점',
      observed: apiCount > 0 ? `비로그인 /api/notes에서 메모 ${apiCount}건이 보임 (HTTP ${api.status})`
        : `비로그인 /api/notes에서 메모가 보이지 않음 (HTTP ${api.status})` },
  ];
}
