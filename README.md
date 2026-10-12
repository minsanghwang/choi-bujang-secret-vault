# BYTE BACK 방어전 시작 틀 R5

## 현재 상태: 2단계 「자료를 코드 밖으로 옮깁니다」

**작동하는 기능**

- `/`는 화면을 보여 주고, 화면은 `/api/notes`를 불러 가상 메모 카드를 그립니다.
- `api/notes.js`는 서버 함수입니다. Vercel 환경변수 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`로 학습용 Supabase 테이블 `defense_notes`를 읽고, `title`·`content`만 돌려줍니다. 키는 브라우저 파일·응답·로그에 나가지 않습니다.
- `/data.json`은 메모 없이 `{"notes": []}`만 돌려줍니다. 빌드는 이 파일을 더 만들지 않고, 메모가 남아 있으면 멈춥니다.
- 빌드(`npm run build`)는 배포의 `/aleph.json`을 계속 만듭니다. `step`은 `aleph.config.json`의 값(2)을 따릅니다.
- `vercel.json`의 `headers`가 모든 응답에 `X-Content-Type-Options: nosniff`, `Content-Security-Policy: frame-ancestors 'none'`, `Referrer-Policy: no-referrer`를 붙입니다. 배포 뒤 `curl -sI https://<배포 주소>/`로 확인합니다.
- `api/ai.js`, `api/threat-intel.js`, `src/decider.mjs`, `src/detect.mjs`는 시작 틀 그대로입니다.

**다시 실행하는 방법**

1. Supabase 대시보드 SQL Editor에 `supabase/step2-defense-notes.sql`을 붙여넣고 Run 합니다. 이 파일은 메모 본문이 있어 Git에는 올리지 않고 `.gitignore`로 제외합니다. 결과 표에서 `rls_enabled`는 true, `anon_select`와 `authenticated_select`는 false, `owner_id_column`은 1, `note_count`는 4여야 합니다.
2. Vercel 프로젝트 설정의 Environment Variables에 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를 **직접** 입력합니다. 값은 Git·채팅·로그에 붙여넣지 않습니다. 저장 뒤 다시 배포해야 반영됩니다.
3. 시험: `npm run test:r5 && npm run test:step2 && npm run test:package` (키 없이 가짜 응답으로 도는 시험이며, 실제 DB나 배포를 증명하지 않습니다.)
4. 배포 화면 `/`에서 카드 네 장이 보이고 `/data.json`에는 메모가 없어야 합니다. 환경변수가 없으면 `/api/notes`가 500(`NOTES_NOT_CONFIGURED`)을 돌려주고 화면에 오류 한 줄이 보입니다.

### 이 단계에 남은 약점

- **서버 함수 `/api/notes`는 아직 공개 주소입니다.** 로그인 확인이 없어서 주소를 아는 누구나 비로그인으로 메모 네 건을 읽을 수 있습니다. 자료를 공개 파일 밖으로 옮겼을 뿐 접근을 막은 것은 아닙니다. 3단계 이후에서 막습니다.
- **과거 노출은 해소되지 않았습니다.** 이전 공개 Git 커밋과 옛 배포에는 가상 메모가 그대로 남아 있습니다. 이 저장소와 옛 배포가 남아 있는 한 과거에 노출된 사실은 사라지지 않습니다.
- `owner_id` 칸은 비어 있고 아직 쓰이지 않습니다.

### 가상 메모가 새 파일에 없는지 확인하는 방법

메모 문장 자체를 이 문서에 적지 않으려고 패턴으로 검색합니다. 아래 결과가 **0건**이면 해당 위치에는 없다는 뜻입니다.

```bash
# GitHub 최신 파일(추적 중인 파일 전체). 결과 없음이 정상입니다.
git grep -nE '실습용 가상 [가-힣]+ 기록' -- . || echo "추적 파일에서 0건"

# 현재 배포 파일. 세 경로 모두 0이 정상입니다.
for p in / /data.json /aleph.json; do
  printf '%s ' "$p"; curl -s "https://<배포 주소>$p" | grep -cE '실습용 가상 [가-힣]+ 기록'
done

# 공개 함수. 2단계에서는 메모가 보이는 것이 알려진 약점입니다.
curl -s "https://<배포 주소>/api/notes"
```

- 위 검색은 **현재** 파일만 봅니다. `git log -p`나 옛 배포 주소로 검색하면 과거 커밋·배포에는 메모가 나옵니다. 이것이 위에 적은 과거 노출입니다.
- `/api/notes`에서 메모가 보이는 것과 `/data.json`에 없는 것을 각각 따로 기록합니다. 하나가 0이라고 다른 하나가 안전하다는 뜻은 아닙니다.
- 공개 키 요청 같은 심판 확인은 심판이 따로 합니다. 이 문서의 검색은 학생의 자기 점검입니다.

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

1단계 시작 틀은 배포 직후 `/`에서 점령된 가상 자료실을 보여 주고 `/data.json`에 같은 가상 메모를 공개했습니다. 2단계에서 이 공개 파일의 메모를 없앴습니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포하고, `api/`의 서버 함수도 함께 배포됩니다. 빌드 명령 `npm run build`는 공개 파일에 메모가 없는지 확인한 뒤(2단계부터 `data.json`을 복사하지 않습니다), Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 1단계에서는 자리표시자였고, 2단계에서 실제 저장소와 배포 주소로 채웠습니다. 이후 단계의 설정과 보호 기능은 코딩 도구가 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 빌드만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 배포된 주소에 비로그인 요청을 보내 `/data.json`에 메모가 없는지, 공개 함수 `/api/notes`가 어떻게 답하는지를 기록합니다. 아직 배포하지 않은 변경은 그 결과에 반영되지 않습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. `public/data.json`을 복사하는 1단계 빌드 흐름은 2단계에서 바꿨습니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
