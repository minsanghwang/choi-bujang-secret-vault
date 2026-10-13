# BYTE BACK 방어전 시작 틀 R5

## 현재 상태: 10단계 「백업에서 자료실을 되살립니다」

## 10단계 복구 경로 요약 (서비스·경로)

| 항목 | 내용 |
|---|---|
| 서비스 | `notes` (가상 메모 자료실) |
| 복구 경로 | `POST /api/restore` (`aleph.config.json`의 `restoreRoute`, 공개 `/aleph.json`의 `restoreRoute`와 같은 값) |
| 구현 파일 | `api/restore.js`, `src/restore-service.mjs` |
| 부르는 사람 | 서버가 검증한 로그인 사용자(`Authorization: Bearer <토큰>` 또는 로그인 쿠키). 사본의 주인 본인, 또는 서버에 등록된 강사(다른 사람의 메모일 때 `ownerId` 필요) |
| 요청 본문 | `{ "id": "<메모 UUID>" }` 필수. 선택: `ownerId`, `contentSha256`(내용 해시), `dryRun`(true이면 쓰지 않고 대상만 확인). 다른 값(`role`, 내용 등)은 `400` |
| 사본 | 비공개 표 `defense_notes_backup`(서버만 읽음). 한 건만 읽어 ID·소유자·내용 해시를 대조하고, 저장된 해시를 내용에서 다시 계산해 맞을 때만 복원합니다 |
| 성공 | `200 { restored: true, created: false\|true, id, ownerId, contentSha256 }` (메모 제목·내용은 응답에 없음) |
| 거부 | 로그인 없음 `401`, 형식 오류 `400`, 남의 메모 `403 not_owner`, 사본 없음·해시 다름 `404`, 사본 검증 실패 `409`(쓰지 않음), 공지 번호·소유자가 다른 자리 `403` |
| 보존 | 대상 한 건 외의 메모는 읽지도 쓰지도 지우지도 않고, 감사 표 `defense_restore_audit`은 덧붙이기만 합니다 |
| 해시 규칙 | `sha256(UTF-8(title) + 0x00 + UTF-8(content))` 소문자 16진수 |
| 정책 사본 | `npm run policy:diff`(차이만 보기), `npm run policy:restore`(보여 주기, `--apply --confirm <해시 12자>`일 때만 적용). 실제 운영 정책은 건드리지 않음 |

**10단계에서 더한 기능**

- **정책 사본 차이 보기**: `npm run policy:diff`는 침해 전에 검증한 안전 정책 사본(`policy/verified/policy-v1.json`, 해시 목록 `policy/verified/MANIFEST.json`)과 현재 시험 정책(`policy/test-policy.json`)의 차이만 보여 줍니다. 사본이 없거나 해시 목록과 다르거나 형식이 틀리면 중단하고 아무것도 쓰지 않습니다. 사본 해시(SHA-256)는 `364f5a32af39e6d2a8b3730cc5a2aef0d206fafe3c0fb8e4068c8902b29aaf0f`입니다. 출력의 앞 12자와 이 값이 같은지 확인하세요.
- **정책 되돌리기**: `npm run policy:restore`는 복원할 버전·해시·바뀔 항목을 보여 주기만 하고, `npm run policy:restore -- --apply --confirm <해시 앞 12자>`일 때만 대상 서비스(`notes`) 하나를 사본으로 바꿉니다. 다른 서비스 규칙은 사본과 달라도 그대로 두고, 감사 이력(`audit`)은 지우지 않고 한 줄을 더합니다. 실제 운영 정책(`src/decider.mjs`, 반 엔진 설정)은 읽지도 바꾸지도 않는 시험용 사본입니다.
- **메모 한 건 복원 경로**: 서비스 `notes`, 경로 `POST /api/restore`(`api/restore.js`, `src/restore-service.mjs`), `aleph.config.json`의 `restoreRoute`에 같은 값을 적었고, 10단계부터 공개 `/aleph.json`에도 `restoreRoute`가 함께 실립니다(심판이 복구 요청을 보낼 주소). 본문은 `{ "id": "<메모 UUID>", "ownerId"?: "<주인 UUID>", "contentSha256"?: "<내용 해시 64자>", "dryRun"?: true|false }`이고 `id`(또는 같은 뜻의 `noteId`)만 필수입니다. 소유자는 서버가 검증한 로그인 사용자이고, `ownerId`·`contentSha256`은 보내면 사본과 대조만 하며(다르면 쓰지 않음) 본문 값으로 권한이 생기지는 않습니다. 해시를 생략하면 그 메모의 가장 오래된(침해 전) 사본을 씁니다. 다른 값(`role`, 내용 등)은 400입니다. 서버는 비공개 사본 표 `defense_notes_backup`에서 그 소유자의 그 한 건만 읽어 ID·소유자(와 보낸 해시)가 같은지, 저장된 해시가 내용에서 다시 계산한 값과 같은지 대조하고, 하나라도 다르면 쓰지 않습니다(404/409). 다른 사람의 메모를 복원하려면 사본의 주인 본인이거나 `INSTRUCTOR_USER_IDS`의 강사가 `ownerId`를 적어야 하고, 아니면 사본을 읽기 전에 `403 not_owner`입니다. 지금 자료실에 같은 번호가 있으면 개인 메모 구역이고 소유자가 같을 때만 제목·내용을 사본 값으로 바꾸고, 없으면 사본의 ID·소유자·위치로 한 건을 만듭니다. 다른 메모와 공지는 읽지도 쓰지도 지우지도 않습니다. `dryRun: true`는 쓰지 않고 대상과 현재 상태(`liveExists`, `liveMatchesCopy`)만 돌려줍니다. 응답에는 메모 제목·내용이 없습니다.
- **감사 기록**: 쓰기 전에 `defense_restore_audit`에 `started`를 남기고(못 남기면 쓰지 않고 503), 끝나면 `restored`/`failed`를 더합니다. 이 표는 덧붙이기만 되고 서버 키로도 고치거나 지울 수 없게 DB 트리거로 막았습니다(SQL을 적용한 뒤).
- **내용 해시 규칙**: `sha256(UTF-8(title) + 0x00 + UTF-8(content))` 소문자 16진수. SQL과 서버가 같은 규칙을 씁니다.

**10단계 실행 순서 (SQL은 직접 검토하고 실행합니다)**

1. `supabase/step10-backup.sql`을 ①→②→③→④ 블록으로 나눠 하나씩 Run 합니다. ③이 지금의 개인 메모를 사전 백업으로 복사하고, ④가 사본을 다시 읽어 `ok_rows`가 `total`과 같은지, 두 표의 `anon`/`authenticated` 권한이 모두 `false`인지 보여 줍니다. 침해 **전**의 정상 상태에서 실행해야 의미가 있습니다.
2. 복원 대상의 `id`(필요하면 `ownerId`·`contentSha256`도)는 시험 계정 B의 메모에 대해 SQL Editor에서 `select note_id, owner_id, content_sha256 from public.defense_notes_backup where owner_id = '<B의 사용자 UUID>';`로 확인합니다(메모 본문은 보지 않아도 됩니다).
3. 먼저 `dryRun: true`로 호출해 대상과 `liveMatchesCopy`를 확인한 뒤, `dryRun`을 빼고 호출합니다. 호출 예(로그인 쿠키가 있는 브라우저 콘솔): `fetch('/api/restore', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id:'<UUID>', ownerId:'<B UUID>', contentSha256:'<해시>', dryRun:true})}).then(r => r.json()).then(console.log)`
   - 정상: B 계정으로 로그인한 상태에서 B의 메모만 `200`, 응답의 세 값이 요청과 같습니다.
   - 거부: A 계정으로 B의 메모를 요청하면 `403 not_owner`, 해시를 바꾸면 `404`, 로그인이 없으면 `401`.
4. 시험: `npm run test:restore`(복원 18건·정책 5건, 가짜 DB·임시 폴더). 실제 DB·배포·심판 판정을 증명하지 않습니다.

**복구 뒤 1~9단계 재확인 순서 (모두 아직 실행하지 않았습니다 = 미실행)**

복구 직후 아래 순서로 확인하고, 실제로 실행한 것만 결과를 적습니다.

| 순서 | 확인 | 정상(허용) | 금지(거부) | 상태 |
|---|---|---|---|---|
| 1 | `npm run policy:diff` | 차이 없음 | 사본 없음·해시 불일치면 중단 | 로컬 실행함(차이 없음) |
| 2 | 로컬 시험 모음(`test:decider`, `test:step2`, `test:r5`, `test:package`, `test:detect`, `test:restore`, `decider:test`, `detect:test`) | 전부 통과 | — | 로컬 실행함 |
| 3 | 1~3단계: 첫 화면·`/data.json` | 화면이 뜸 | `/data.json`에 메모 없음 | **미실행**(배포 대상) |
| 4 | 3~4단계: A 로그인 후 자기 메모 읽기·추가·수정·삭제 | `200`·`201` | 로그인 없는 `/api/notes`는 `401`, 가짜 토큰 `401` | **미실행** |
| 5 | 4단계: B가 A의 메모 번호를 `GET`·`PUT`·`DELETE` | — | 모두 `403`(`X-Deny-Reason: owner_mismatch`) | **미실행** |
| 6 | 5단계: 공개 키로 원본 API 직접 요청 | — | `401`/`403`/빈 목록 | **미실행**(`step5-revoke-direct.sql` 적용 여부도 미확인) |
| 7 | 6~7단계: 미등록 기기·이상 접속 요청 | 정상 요청 허용 | `device_not_registered` 거부, 복합 이상은 `step_up` | **미실행**(심판이 보냄, 로컬은 `decider:test`만) |
| 8 | 8단계: 공지 목록·일반 학생의 공지 수정 | 공지 목록 `200` | 공지 수정 `403 instructor_required` | **미실행**(복구 뒤 재확인 전) |
| 9 | 9단계: 정상 기기·폭주 조회 사건 | 정상은 `observe` | 10분 120건 초과는 `propose_revocation` | **미실행**(심판이 보냄, 로컬은 `detect:test`만) |
| 10 | 10단계: B의 메모 한 건 복원 | `200`, 세 값 일치 | A의 요청 `403`, 해시 불일치 `404`/`409` | 정상 복원은 배포에서 실행함(아래 기록). A의 요청 `403`·해시 불일치·로그인 없음은 **미실행**(가짜 DB 시험만) |

**10단계 실제 실행 기록 (2026-10-13, 배포 db506d8, 직접 실행한 것만)**

- `supabase/step10-backup.sql`의 ②~④를 학생이 Supabase에서 적용했고, ④에서 `anon`·`authenticated` 권한 네 값이 모두 `false`였습니다. 적용 뒤 Supabase에서 읽어 `defense_notes_backup` 5행(주인 있는 개인 메모 5건), `defense_restore_audit` RLS 켜짐을 확인했습니다. ④의 `total`/`ok_rows` 숫자는 학생에게서 받지 못했지만, 아래 해시 대조에서 5건 모두 사본 해시와 같았습니다.
- 시험 계정 B(사용자 ID `04495177…`, 메모 `ee6f1bd8…` 한 건)로 로그인해 `POST /api/restore`를 호출했습니다. `dryRun`은 `200`(`liveExists: true`; 출력이 잘려 `liveMatchesCopy` 값은 기록하지 못함), 실제 복원은 `200 {restored: true, created: false}`이고 응답의 ID·소유자·내용 해시가 사본과 같았습니다.
- 복원 뒤 DB 읽기: 5건 모두 현재 내용 해시가 사본 해시와 같고(`true`), 메모는 6행(개인 메모 5 + 공지 1)·사본 5행 그대로이며, 감사 표에는 `planned`, `started`, `restored`, `started`, `restored` 5줄이 순서대로 쌓였습니다(실제 복원 호출이 두 번 기록됨). 감사 기록은 한 줄도 줄지 않았습니다.
- 복원 전에 메모를 일부러 바꿔 보지 않았습니다. 그래서 이 실행은 "바뀐 메모가 되돌아왔다"가 아니라 "사본 값과 같은 상태가 확인됐다"까지만 증명합니다.
- 아직 배포에서 실행하지 않은 것: A 계정이 B의 메모를 복원하려는 요청의 `403`, 해시를 바꾼 요청의 `404`, 로그인 없는 `401`, 위 표의 3~9번.

복구 뒤에 "자료와 정책이 돌아왔다"는 말은 3~10을 직접 실행해 결과를 적은 뒤에만 합니다.

**9단계에서 더한 기능**

- 탐지 함수 `src/detect.mjs`의 `detect(events)`가 가상 사건에서 가명 `identity.sub`, `at`, `method` 세 값만 읽습니다. 모양이 맞지 않는 사건(형식이 틀린 시각, 이메일·실명 모양의 `sub`, 객체가 아닌 값)은 정상값으로 채우지 않고 버립니다. 메모 내용·토큰·실명 같은 다른 필드는 읽지도 복사하지도 출력하지도 않습니다.
- 규칙은 하나입니다. 같은 `sub`의 `GET`이 어느 10분 구간에서든 **120건을 넘을 때만** 의심으로 표시합니다. 정확히 120건, 서로 다른 사용자의 합산, 10분 밖으로 흩어진 조회는 의심이 아닙니다. 지역 같은 신호는 쓰지 않습니다.
- 의심이면 별도의 탐지 결과 `{ action: 'propose_revocation', reasonCode: 'burst_read', subject: <그 sub> }`를 돌려주고, 아니면 `{ action: 'observe' }`입니다. 여러 사용자가 동시에 걸리면 한도를 가장 먼저 넘긴 한 명만 제안합니다. 접속 허용/거부 응답(`decide`)과 회수 API는 건드리지 않았고, 이 함수는 기기 권한을 바꾸지 않습니다. 실제 회수와 걸린 시간은 운영 엔진과 심판이 확인합니다.
- 시험: `npm run test:detect`(경계값·입력 처리), `npm run detect:test`(가상 사건 연습 6건). 두 명령 모두 로컬 연습이며 실제 사건 전달·접속 회수·심판 통과를 증명하지 않습니다.

**작동하는 기능**

- 자료실을 두 구역으로 나누고 자원 ID를 따로 표시합니다(`src/zones.mjs`). `note:<id>` = 내 자료실 메모(주인만), `notice:<id>` = 강사 공지(읽기는 로그인한 사용자, 수정은 서버에 강사로 저장된 계정만). 자료 API는 한 건 요청마다 응답 헤더 `X-Resource-Id`로 이 ID를 알리고, 거부하면 본문 대신 짧은 헤더 `X-Deny-Reason`(`owner_mismatch`, `owner_missing`, `instructor_required`, `wrong_zone`, `unknown_zone`, `owner_change`)을 남깁니다. 본문 형식과 기존 주소 `/api/notes`, `/api/notes/:id`, 화면과 메뉴는 그대로입니다.
- 새 주소 `/api/notices`(`api/notices.js`, `GET` 공지 목록, 로그인한 사용자 모두)와 `/api/notices/:id`(`api/notices/[id].js`): `GET` 읽기, `PUT` 수정(강사만)만 있고 추가·삭제는 없습니다(405). 구역 열이 없는 DB에서는 공지 목록이 빈 배열입니다. 공지는 제목·내용만 바꾸며 소유자와 구역은 바뀌지 않습니다.
- 자료 API의 최종 확인: 검증된 사용자 ID(`src/verify-login.mjs`)와 DB에 **저장된** 행의 구역·`owner_id`, 서버 환경변수 `INSTRUCTOR_USER_IDS`(강사 사용자 UUID를 쉼표로 구분, 비어 있으면 강사 없음)만 비교합니다. 화면 메뉴와 요청 본문·헤더의 `role`·`owner_id`·`zone`은 읽지 않습니다. 개인 메모 주소로 공지를, 공지 주소로 개인 메모를 요청하면 강사여도 `403 wrong_zone`입니다.
- 판정기 `src/decider.mjs`(`RULE_IDS`: `device_registered`, `zone_access`, `step_up_required`)에 구역 규칙 `zone_access`가 있습니다. 엔진이 확인한 `service`·`method`·`path`·`route`가 구역 표의 한 줄과 정확히 맞을 때만 통과합니다. 표는 프롬프트가 요구한 세 규칙, 즉 자기 메모 읽기(`GET /notes/:id`)·수정(`PUT /notes/:id`)과 강사 공지 수정(`PUT /notices/:id`, 허용하지 않음)뿐이며, 메모 목록·추가·삭제도 판정기 표에는 없습니다(자료 API는 그대로 처리합니다). 그 밖에 표에 없는 경로·메서드와 `route`의 불일치·쿼리가 붙은 요청(`queryLength` ≠ 0)·`:id` 자리의 `export` 같은 기능 이름·더 깊은 경로는 `deny`와 `zone_not_allowed`입니다. 자료는 쿼리가 아니라 경로의 ID 한 칸으로만 고르고, 그 ID는 UUID이거나 7단계 엔진 예시의 `demo`(자기 메모의 정상 요청)일 때만 인정하고, 그 밖의 이름(`other-1`, `learner_…`, `notice…` 등)은 모두 `deny`·`zone_not_allowed`입니다. 요청 계약에 소유자 값이 없어서, 판정기는 허용한 메모 경로를 처음 쓴 사용자(`subjectId`)를 소유 기록(프로세스 메모리, 최대 5000건)에 남기고 같은 경로를 다른 사용자가 요청하면 `deny`·`zone_not_allowed`로 거부합니다. 먼저 접근한 쪽이 주인이 되는 방식이고 서버가 다시 뜨면 기록이 사라지므로 최종 소유자 확인은 자료 API가 합니다. 공지 읽기·수정(`GET·PUT /notices/:id`)은 요청 계약에 강사 역할 값이 없어 판정기가 허용하지 않습니다(공지 읽기는 자료 API가 로그인한 사용자에게 허용하지만 판정기 표에는 없습니다). 6단계 기기 규칙과 7단계 추가 확인 규칙은 그대로이고 순서는 기기 → 구역 → 추가 확인입니다.
- `aleph.config.json`: `step` 10, `restoreRoute` `POST /api/restore`. `allowedRoutes`는 구현한 메서드와 경로를 `GET /api/notes`처럼 한 줄씩 적습니다(`GET·POST /api/notes`, `GET·PUT·DELETE /api/notes/:id`, `GET /api/notices`, `GET·PUT /api/notices/:id`). 자기 점검에 구역 간 직접 요청(`cross_zone_direct_api`)과 9단계 탐지·회수(`doppelganger_burst_revocation`)를 미실행으로 기록합니다.

**다시 실행하는 방법 (SQL은 직접 검토하고 실행합니다)**

1. `supabase/step8-zones.sql`을 ①②③ 블록으로 나눠 Run 하면 `defense_notes`에 `zone` 열(`note`/`notice`)이 생기고 공개 가능한 가상 공지 한 건이 들어갑니다. 실행 전에는 서버가 모든 행을 개인 메모로 보므로 앱은 그대로 동작하고 공지 목록은 비어 있습니다.
2. 강사를 쓰려면 Vercel 환경변수 `INSTRUCTOR_USER_IDS`에 강사 계정의 사용자 UUID를 직접 넣고 재배포합니다. (비밀번호·키가 아니지만 코드와 Git에는 넣지 않습니다.)
3. 시험: `npm run test:decider && npm run test:step2 && npm run test:r5 && npm run test:package`, 그리고 `npm run decider:test` (가상 요청과 가짜 DB로 도는 시험이며 실제 DB·배포·심판 판정을 증명하지 않습니다.)
4. 직접 API 확인(예시, 로그인 후 쿠키 사용 또는 `Authorization` 헤더): B 계정으로 A 메모 번호를 `GET /api/notes/<번호>` 하면 `403`이고 자료가 없어야 합니다. 일반 학생이 `PUT /api/notices/<번호>` 하면 `403`(`X-Deny-Reason: instructor_required`)이어야 합니다. 본인 메모 읽기·수정은 그대로 `200`입니다.

### 이 단계에 남은 약점

- 10단계: 복원 경로는 사본 주인 본인도 부를 수 있어서, 계정 자체가 침해되면 그 계정이 자기 메모를 사본 값으로 되돌리는 것은 막지 못합니다(다른 사람의 메모는 못 건드립니다). 사본은 같은 Supabase 프로젝트의 비공개 표라서, DB 전체가 침해되면 사본도 함께 바뀔 수 있습니다. 정책 사본의 해시는 저장소 안의 목록과 README에 있어서 저장소를 쓸 수 있는 사람은 둘 다 바꿀 수 있고, `policy/test-policy.json`은 실제 운영 정책이 아니라 시험용 사본입니다. `POST /api/restore`는 판정기 구역 표에 없어서(기본 거부) 엔진을 거치는 경로로 허용되려면 운영 측 허용 규칙이 별도로 필요하고, `restoreRoute`의 표기 형식은 운영 계약으로 확인하지 못했습니다. `step10-backup.sql` 적용과 B의 메모 한 건 정상 복원은 실제로 실행했지만(위 기록), 거부 요청(A의 `403` 등)과 복원 전 변조 메모의 되돌림은 배포에서 확인하지 않았습니다.

- 9단계 탐지는 `docs/DETECT_EVENTS.md`의 사건 세 값(`at`, `method`, `identity.sub`)만 봅니다. 사건에 네트워크·기기 값이 없어서 "평소와 다른 네트워크"는 판단하지 않고, 회수 대상도 기기가 아니라 `subject` 하나입니다. 120건 이하로 천천히 읽거나 여러 계정으로 나눠 읽는 도플갱어는 지나갑니다. 운영 엔진이 사건을 전달하고 회수 제안을 집행하는 경로는 이 저장소에서 연결·확인하지 않았습니다.

- 판정기는 메모의 주인이 누구인지 알 수 없습니다(`subjectId`는 가명이고 요청 계약에 소유자·역할 값이 없습니다). 소유자·강사 대조는 자료 API만 하므로, 판정기만으로는 B가 A의 메모 번호를 요청하는 것을 막지 못합니다. 강사 공지 수정은 판정기가 모두 거부하므로 엔진을 거치는 경로에서는 강사도 수정할 수 없습니다. 엔진이 강사 역할을 별도 계약으로 제공하면 그때 허용 조건을 추가해야 합니다.
- `zone_not_allowed` 이유 코드는 운영 등록부의 `allowedReasonCodes`에 있어야 합니다. 등록되지 않았다면 엔진이 응답을 거부해 접근이 막힙니다(허용으로 바뀌지는 않습니다).
- 강사 목록은 환경변수 하나이고 이력·만료가 없습니다. 공지 목록 조회(`GET /api/notices`)는 있지만 공지 작성 API는 만들지 않았습니다.
- 구역 시험은 대부분 가짜 DB로 했습니다. `supabase/step8-zones.sql` 적용 뒤 배포에서 공지 목록 1건과 일반 학생의 공지 수정 `403 instructor_required`는 직접 확인했지만, B가 A의 메모를 읽는 요청은 배포에서 직접 확인하지 않았습니다.

- 이상 접속 기준(0~5시, 10건 이상 등)은 가상 사건에 맞춘 임의 값이고, 실제 사용자의 평소 패턴을 학습한 것이 아닙니다. 세 조건이 모두 맞지 않으면 걸리지 않아, 더 약하게 섞인 이상 접속은 지나갈 수 있습니다. 위치·네트워크 신호는 현재 실제 경로에서는 `unknown`이라 가상 사건에서만 작동합니다. 판정기 연습은 가상 요청이며 실제 엔진 연결과 재로그인 차단은 증명하지 않습니다.

- `supabase/step5-revoke-direct.sql`은 제안이고, 적용 여부와 결과는 이 저장소가 증명하지 않습니다. 실행 전에는 DB의 실제 권한 상태를 `has_table_privilege`로 직접 확인해야 합니다. 원본 직접 요청은 심판이 `anon` 키로 확인하고, 로그인한 사용자 토큰으로 직접 부르는 `authenticated` 경로는 심판이 재현하지 않는 범위입니다.
- 서버 함수 하나가 모든 메모 접근을 맡습니다. 이 함수의 로그인·소유자 검사가 깨지면 `service_role`이 RLS를 우회하므로 그대로 노출됩니다. 시험은 가짜 응답과 메모리 DB로만 했습니다.
- 로그인을 서버 함수로 옮긴 변경은 시험을 가짜 클라이언트로만 했고, 실제 배포에서 로그인이 되는지는 이 저장소가 증명하지 않습니다. 깨지면 이 변경의 커밋만 `git revert`로 되돌립니다. 공개 키는 화면 코드에는 없지만 `aleph.config.json`과 `/aleph.json`의 `database.publishableKey`에는 심판 확인용으로 그대로 있습니다(공개 값). 로그인 시도 횟수를 서버에서 제한하는 장치는 없고 Supabase Auth의 기본 제한에 맡깁니다.
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

`vercel.json`은 정적 결과물 `public`을 배포하고, `api/`의 서버 함수도 함께 배포됩니다. 빌드 명령 `npm run build`는 공개 파일에 메모가 없는지 확인하고(2단계부터 `data.json`을 복사하지 않습니다) (로그인이 서버로 옮겨져 SDK를 화면에 복사하지 않습니다) Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 1단계에서는 자리표시자였고, 2단계에서 실제 저장소와 배포 주소로 채웠습니다. 이후 단계의 설정과 보호 기능은 코딩 도구가 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 빌드만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 배포된 주소에 비로그인 요청과 서명 없는 가짜 토큰 요청을 보내 `/data.json`에 메모가 없는지, `/api/notes`가 거부하는지를 기록합니다. 정상 A 로그인 점검은 계정 정보 없이 실행되므로 미실행으로 남깁니다. 아직 배포하지 않은 변경은 그 결과에 반영되지 않습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. `public/data.json`을 복사하는 1단계 빌드 흐름은 2단계에서 바꿨습니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
