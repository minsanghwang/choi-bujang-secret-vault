const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u;
const REPO = /^[A-Za-z0-9._-]{1,100}$/u;
const SHA = /^[a-f0-9]{40}$/iu;
const HOST = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app$/iu;

export function deploymentIdentity(env, config) {
  const owner = env.VERCEL_GIT_REPO_OWNER;
  const repo = env.VERCEL_GIT_REPO_SLUG;
  const commit = env.VERCEL_GIT_COMMIT_SHA;
  // 운영(production) 배포는 배포마다 새로 생기는 미리보기 주소(VERCEL_URL)가 아니라
  // 로그인 없이 열리는 대표 주소를 알립니다. 심판은 이 주소로 요청합니다.
  const host = env.VERCEL_ENV === 'production' && env.VERCEL_PROJECT_PRODUCTION_URL
    ? env.VERCEL_PROJECT_PRODUCTION_URL : env.VERCEL_URL;
  if (env.VERCEL_GIT_PROVIDER !== 'github' || !OWNER.test(owner || '')
      || !REPO.test(repo || '') || repo === '.' || repo === '..'
      || repo.toLowerCase().endsWith('.git') || !SHA.test(commit || '')
      || !HOST.test(host || '') || !Number.isInteger(config?.step)
      || config.step < 1 || config.step > 12
      || typeof config.judgeIssuer !== 'string'
      || !/^https:\/\/[a-z0-9-]+\.up\.railway\.app\/defense\/judge$/iu.test(config.judgeIssuer)
      || typeof config.sampleMarker !== 'string'
      || !/^[A-Z0-9_]{1,80}$/u.test(config.sampleMarker)) {
    throw new Error('배포 식별 정보를 확인할 수 없습니다. Vercel 시스템 환경변수와 aleph.config.json의 step을 확인하세요.');
  }
  const identity = {
    schema: 'aleph.defense.deployment.v1',
    step: config.step,
    repoUrl: `https://github.com/${owner.toLowerCase()}/${repo.toLowerCase()}`,
    commit: commit.toLowerCase(),
    publicAppUrl: `https://${host.toLowerCase()}`,
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  };
  // 3단계부터 로그인 발급자(공개 정보)와 허용 경로도 함께 알립니다. 비밀 값은 넣지 않습니다.
  if (config.step >= 3) {
    identity.identityProvider = config.identityProvider ?? null;
    identity.allowedRoutes = config.allowedRoutes ?? [];
  }
  // 5단계부터 원본 자료 API 주소와 공개 접속 정보(공개 키만)도 알립니다. 서버 전용 키는 넣지 않습니다.
  if (config.step >= 5) {
    identity.originalApiUrl = config.originalApiUrl ?? null;
    identity.database = config.database ?? null;
  }
  // 10단계부터 복구 경로(공개 정보)도 알립니다. 심판이 이 주소로 복구 요청을 보냅니다.
  if (config.step >= 10) identity.restoreRoute = config.restoreRoute ?? null;
  return identity;
}
