# BYTE BACK 방어전 시작 틀 R5

## 현재 상태: 5단계 「자료 요청을 서버 한곳으로 모읍니다」

**작동하는 기능**

- 브라우저의 메모 읽기·추가·수정·삭제는 모두 Vercel 서버 함수(`/api/notes`, `/api/notes/:id`)로만 갑니다. `public/index.html`이 Supabase에 직접 부르는 것은 로그인·로그아웃·세션 읽기(`client.auth.*`)뿐이고, 메모 자료를 Supabase에서 직접 읽거나 고치는 코드는 없습니다(5단계에서 확인했고 변경하지 않았습니다).
- 서버 함수는 4단계 그대로입니다. 모든 요청의 토큰을 `src/verify-login.mjs`로 검사하고(없거나 틀리면 `401 {"error":"LOGIN_REQUIRED"}`), 검증된 사용자 ID와 행의 `owner_id`를 비교해 본인 메모만 허용합니다(남의 것·주인 없는 행 403, 없는 번호 404, 소유자 변경 시도 403). 서버는 `SUPABASE_URL`·`SUPABASE_SECRET_KEY`(서버 전용)로 `defense_notes`를 읽고 씁니다.
  - `GET·POST /api/notes`, `GET·PUT·DELETE /api/notes/:id` (본문 `{title, body}`, 응답 `{id,title,body}`)
- `aleph.config.json`: `step` 5, `allowedRoutes`(`/api/notes`, `/api/notes/:id`), `identityProvider`(로그인 발급자), **`originalApiUrl`**(쿼리 없는 원본 자료 HTTPS 경로 `https://…supabase.co/rest/v1/defense_notes`), `database`(공개 접속 정보: Project URL·publishable key·테이블 이름. 서버 전용 키는 없습니다). `/aleph.json`은 계속 만들어지고 5단계부터 `originalApiUrl`과 `database`도 담습니다.
- `/data.json`은 `{"notes": []}`입니다. `vercel.json`의 `headers`가 모든 응답에 `X-Content-Type-Options: nosniff`, `Content-Security-Policy: frame-ancestors 'none'`, `Referrer-Policy: no-referrer`를 붙입니다. 운영 배포의 `/aleph.json`은 `publicAppUrl`에 로그인 없이 열리는 대표 주소를 적습니다.
- `api/ai.js`, `api/threat-intel.js`, `src/decider.mjs`, `src/detect.mjs`, `src/verify-login.mjs`는 그대로입니다.

**다시 실행하는 방법 (SQL은 직접 검토하고 실행합니다)**

1. 4단계까지의 준비(계정 A·B, `supabase/step4-owner-link.sql`, Vercel 환경변수 `SUPABASE_URL`·`SUPABASE_SECRET_KEY`)가 돼 있어야 합니다. `supabase/step4-rls-grants.sql`의 ②(authenticated에 권한 부여)는 5단계와 반대이니 실행하지 마세요.
2. `supabase/step5-revoke-direct.sql`을 ①②③ 블록으로 나눠 한 블록씩 Run 합니다. `PUBLIC`·`anon`·`authenticated`의 직접 권한을 거두고 `service_role`만 남깁니다. 적용 전후에 `has_table_privilege`와 `information_schema.role_table_grants`로 대조합니다. 정상은 `anon`과 `authenticated`가 네 가지 모두 `granted = false`이고, 두 번째 조회가 0행인 것입니다.
3. 시험: `npm run test:r5 && npm run test:step2 && npm run test:package` (가짜 응답과 메모리 DB로 도는 시험이며 실제 DB·배포를 증명하지 않습니다.)
4. 일반 창에서 A로 로그인해 메모 읽기·추가·수정·삭제가 되는지, 시크릿 창에서 B로 로그인했을 때 A의 메모가 보이지 않는지, 로그인 없이 `curl -s -i https://<배포 주소>/api/notes`가 `401`과 JSON 오류 문구인지 확인합니다.
5. 공개 키로 원본 저장소를 직접 불러 봅니다(메모가 없어야 합니다). 권한을 거둔 뒤에는 `401` 또는 `403`(`permission denied`)이 옵니다.
   `curl -s -i -H "apikey: <publishable key>" "<originalApiUrl>"`

### 이 단계에 남은 약점

- `supabase/step5-revoke-direct.sql`은 제안이고, 적용 여부와 결과는 이 저장소가 증명하지 않습니다. 실행 전에는 DB의 실제 권한 상태를 `has_table_privilege`로 직접 확인해야 합니다. 원본 직접 요청은 심판이 `anon` 키로 확인하고, 로그인한 사용자 토큰으로 직접 부르는 `authenticated` 경로는 심판이 재현하지 않는 범위입니다.
- 서버 함수 하나가 모든 메모 접근을 맡습니다. 이 함수의 로그인·소유자 검사가 깨지면 `service_role`이 RLS를 우회하므로 그대로 노출됩니다. 시험은 가짜 응답과 메모리 DB로만 했습니다.
- 화면 코드에는 로그인용 Supabase 공개 키(`sb_publishable_…`)가 아직 들어 있습니다. 로그인까지 서버 함수로 옮기는 것은 이번에 하지 않았습니다.
- 회원가입 화면은 없습니다. 계정은 Supabase 대시보드에서 만듭니다.
- **과거 노출은 해소되지 않았습니다.** 이전 공개 Git 커밋과 옛 배포에는 가상 메모가 그대로 남아 있습니다. 이 저장소와 옛 배포가 남아 있는 한 과거에 노출된 사실은 사라지지 않습니다.

### 가상 메모가 새 파일에 없는지 확인하는 방법

메모 문장 자체를 이 문서에 적지 않으려고 패턴으로 검색합니다. 아래 결과가 **0건**이면 해당 위치에는 없다는 뜻입니다.

```bash
# GitHub 최신 파일(추적 중인 파일 전체). 결과 없음이 정상입니다.
git grep -nE '실습용 가상 [가-힣]+ 기록' -- . || echo "추적 파일에서 0건"

# 현재 배포 파일. 세 경로 모두 0이 정상입니다.
for p in / /data.json /aleph.json; do
  printf '%s ' "$p"; curl -s "https://<배포 주소>$p" | grep -cE '실습용 가상 [가-힣]+ 기록'
done

# 로그인 없는 함수 호출. 401과 JSON 오류 문구만 와야 합니다(메모가 보이면 안 됩니다).
curl -s -i "https://<배포 주소>/api/notes"
```

- 위 검색은 **현재** 파일만 봅니다. `git log -p`나 옛 배포 주소로 검색하면 과거 커밋·배포에는 메모가 나옵니다. 이것이 위에 적은 과거 노출입니다.
- `/api/notes`의 거부 결과와 `/data.json`에 메모가 없는 것을 각각 따로 기록합니다. 하나가 0이라고 다른 하나가 안전하다는 뜻은 아닙니다.
- 공개 키 요청 같은 심판 확인은 심판이 따로 합니다. 이 문서의 검색은 학생의 자기 점검입니다.

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

1단계 시작 틀은 배포 직후 `/`에서 점령된 가상 자료실을 보여 주고 `/data.json`에 같은 가상 메모를 공개했습니다. 2단계에서 이 공개 파일의 메모를 없앴습니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포하고, `api/`의 서버 함수도 함께 배포됩니다. 빌드 명령 `npm run build`는 공개 파일에 메모가 없는지 확인하고(2단계부터 `data.json`을 복사하지 않습니다) 로그인용 SDK 번들을 `public/vendor/`에 복사한 뒤, Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 1단계에서는 자리표시자였고, 2단계에서 실제 저장소와 배포 주소로 채웠습니다. 이후 단계의 설정과 보호 기능은 코딩 도구가 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 빌드만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 배포된 주소에 비로그인 요청과 서명 없는 가짜 토큰 요청을 보내 `/data.json`에 메모가 없는지, `/api/notes`가 거부하는지를 기록합니다. 정상 A 로그인 점검은 계정 정보 없이 실행되므로 미실행으로 남깁니다. 아직 배포하지 않은 변경은 그 결과에 반영되지 않습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. `public/data.json`을 복사하는 1단계 빌드 흐름은 2단계에서 바꿨습니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
