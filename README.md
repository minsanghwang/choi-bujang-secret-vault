# BYTE BACK 방어전 시작 틀 R5

## 현재 상태: 12단계 「탈환 작전실을 완성합니다」

## 보너스 xdr-01 「무차별 로그인 공격을 잡아 냅니다」

| 항목 | 내용 |
|---|---|
| 경보 읽기 | `xdr/brute-force/read-alerts.mjs`(확인용, `decide.mjs`가 불러오지 않음): `xdr/fixtures/brute-force.json`의 Wazuh 경보에서 시각·출발 주소·계정·규칙 수준·설명만 뽑고, 비밀값처럼 보이는 값은 가립니다. 실행 `node xdr/brute-force/read-alerts.mjs` → `경보 28건 · 뽑은 줄 28줄 · 같음` |
| 패턴 목록 | `xdr/brute-force/patterns.json`: MITRE ATT&CK T1110 근거의 두 패턴만. `same_source_failure_burst`(T1110.001 Password Guessing, 같은 주소의 짧은 시간 연속 실패), `password_spraying`(T1110.003, 여러 계정에 같은 비밀번호). 패턴마다 근거 한 줄 |
| 판단 모듈 | `xdr/brute-force/decide.mjs`: 패턴을 파일 맨 위 상수로 옮겨 적고 `decide(alert)` 하나를 내보냅니다. **import·파일 읽기/쓰기·네트워크 없음.** T1110 표시가 없으면 `record`. T1110이면 기본 0.5에 실패 건수(10·15·30건 이상)·규칙 수준(8·10·12 이상)·여러 계정 대입을 더해 확신도를 매기고, 0.85 이상 `block`, 0.5 이상 `alert`, 그 아래 `record`. "실패 뒤 성공했습니다"는 사용자 실수일 수 있어 `block`하지 않습니다. Wazuh가 문자열로 담는 건수(`"48"`)는 숫자만 있을 때만 읽습니다 |
| 알림과 차단 | `xdr/brute-force/respond.mjs`(`npm run xdr:respond`): `result.json`의 `block`만 출발 주소별 거부 규칙(`xdr/brute-force/deny-rules.json`, 규칙 `xdr_brute_force_block`, 근거 경보 번호, 근거 경보 시각부터 60분 뒤 만료)으로 내보내고, `block`·`alert`를 `xdr/alerts.log`에 한 줄씩 쌓습니다(같은 경보는 다시 쓰지 않음). 같은 주소에 정상 기록(`record`)이나 "실패 뒤 성공"이 있으면 규칙에 넣지 않습니다 |
| 판정기 연결 | 판정기 요청 계약(`docs/DECIDER_REQUEST.md`)에 출발 주소가 없어 `src/decider.mjs`의 `decide()`는 주소를 볼 수 없습니다. 그래서 **판정기의 기존 규칙과 코드는 바꾸지 않고**, 판정기에 확인 단계를 하나 더하는 부품으로 `checkAddress(rules, address, at)`을 둡니다. 요청이 판정기에 닿기 전에 출발 주소가 만료 전 거부 규칙에 걸리면 `deny · xdr_brute_force`를 돌려주고, 아니면 판정기로 넘깁니다. 실제 엔진 앞단에 이 부품을 꽂는 것은 운영 측 연결이 필요하며 이 저장소에서 확인하지 않았습니다 |
| 실행 결과 (2026-10-14, 로컬) | `npm run xdr:run -- brute-force` → `block 10 · alert 9 · record 9`(bf-01~10 명확한 공격, bf-11~19 애매한 시도, bf-20~28 정상 이벤트). 정상 이벤트를 `block`한 경우 0건. `npm run xdr:respond` → 거부 규칙 9개(근거 경보 10건), 다시 흘리기: 명확한 공격 막힘 10/10 · 애매한 시도 막힘 0 · 정상 이벤트 막힘 0 |
| 시험 | `node --test test/xdr-brute-force.test.mjs`(로컬 시험 경보, 심판 판정 아님). 심판은 격리 환경에서 `decide.mjs` 한 파일만 다시 불러 결과를 봅니다 |

## 보너스 xdr-02 「웹 주입 공격을 잡아 냅니다」

| 항목 | 내용 |
|---|---|
| 경보 읽기 | `xdr/web-injection/read-alerts.mjs`(확인용, `decide.mjs`가 불러오지 않음): `xdr/fixtures/web-injection.json`에서 시각·출발 주소·계정·규칙 수준·설명만 뽑고 비밀값처럼 보이는 값은 가립니다. 실행 `node xdr/web-injection/read-alerts.mjs` → `경보 26건 · 뽑은 줄 26줄 · 같음` |
| 패턴 목록 | `xdr/web-injection/patterns.json`: MITRE ATT&CK T1190 근거의 네 패턴. `sql_injection`(요청 인자 안 SQL 구문), `script_injection`(스크립트 태그·삽입 표식), `path_traversal`(`../` 반복), `command_separator`(명령 구분자). 패턴마다 근거 한 줄 |
| 판단 모듈 | `xdr/web-injection/decide.mjs`: 패턴을 파일 맨 위 상수로 옮겨 적고 `decide(alert)` 하나를 내보냅니다. **import·파일 읽기/쓰기·네트워크 없음.** T1190 표시가 없으면 `record`. T1190이면 기본 0.5에 같은 주소 반복 횟수(2·5·10번 이상)와 규칙 수준(8·10·12 이상)을 더합니다. **주입 표기가 있고 5번 이상 반복된 경우만** `block`(0.85 이상)까지 가고, 한 번뿐인 표기(수업명 "select", "SQL 공지" 등)는 `alert`까지만 갑니다 |
| 알림과 차단 | `xdr/web-injection/respond.mjs`(`npm run xdr:respond:web`): `block`만 출발 주소별 거부 규칙(`xdr/web-injection/deny-rules.json`, 규칙 `xdr_web_injection_block`, 근거 경보 번호, 60분 뒤 만료)으로 내보내고, `block`·`alert`를 `xdr/alerts.log`에 한 줄씩 쌓습니다(요청 주소 문자열은 쓰지 않음, 같은 경보는 다시 쓰지 않음). 정상 기록이 있는 주소는 규칙에 넣지 않습니다. 판정기 연결 방식은 xdr-01과 같습니다(`checkAddress`, 판정기 코드는 그대로) |
| 실행 결과 (2026-10-14, 로컬) | `npm run xdr:run -- web-injection` → `block 8 · alert 9 · record 9`(wi-01~08 반복된 주입, wi-09~17 한 번뿐인 표기, wi-18~26 정상 이벤트). 정상 이벤트를 `block`한 경우 0건. `npm run xdr:respond:web` → 거부 규칙 7개(근거 경보 8건), 다시 흘리기: 명확한 공격 막힘 8/8 · 애매한 시도 0 · 정상 이벤트 0 |
| 시험 | `node --test test/xdr-web-injection.test.mjs`(로컬 시험 경보, 심판 판정 아님) |

## 보너스 xdr-03 「알려진 취약점 악용을 잡아 냅니다」

| 항목 | 내용 |
| --- | --- |
| 경보 읽기 | `xdr/known-cve/read-alerts.mjs`(확인용, `decide.mjs`가 불러오지 않음): `xdr/fixtures/known-cve.json`에서 시각·출발 주소·계정·규칙 수준·설명만 뽑고 비밀값처럼 보이는 값은 가립니다. 실행 `node xdr/known-cve/read-alerts.mjs` → `경보 24건 · 뽑은 줄 24줄 · 같음` |
| 패턴 목록 | `xdr/known-cve/patterns.json`: CVE-2021-44228 · MITRE ATT&CK T1190 근거의 세 패턴. `jndi_lookup`(완전한 `${jndi:ldap://…}` 구문), `jndi_obfuscated`(글자를 쪼개거나 부호화해 감춘 같은 구문), `known_scanner_trace`(점검 도구 흔적, 약한 신호). 패턴마다 근거 한 줄 |
| 판단 모듈 | `xdr/known-cve/decide.mjs`: 패턴을 파일 맨 위 상수로 옮겨 적고 `decide(alert)` 하나를 내보냅니다. **import·파일 읽기/쓰기·네트워크 없음.** T1190 표시가 없으면 `record`. **완전한 원격 조회 구문이 있을 때만** 기본 0.5에 0.35를 더해 `block`(0.85 이상)에 닿고, 머리글·주소 양쪽 / 5번 이상 반복 / 점검 흔적 / 수준 12 이상이면 더합니다. 단어·조각·이름만 있으면 0.84를 넘지 않아 `alert`까지만 갑니다. 주소 부호화(`%24%7Bjndi:`)는 풀어서 봅니다 |
| 알림과 차단 | `xdr/known-cve/respond.mjs`(`npm run xdr:respond:cve`): `block`만 출발 주소별 거부 규칙(`xdr/known-cve/deny-rules.json`, 규칙 `xdr_known_cve_block`, 근거 경보 번호, 60분 뒤 만료)으로 내보내고, `block`·`alert`를 `xdr/alerts.log`에 한 줄씩 쌓습니다(요청 주소 문자열은 쓰지 않음). 정상 기록이 있는 주소는 규칙에 넣지 않습니다. 판정기 연결 방식은 xdr-01과 같습니다(`checkAddress`, 판정기 코드는 그대로, 실제 엔진 연결은 이 저장소에서 확인하지 않았습니다) |
| 실행 결과 (2026-10-14, 로컬) | `npm run xdr:run -- known-cve` → `block 8 · alert 8 · record 8`(kc-01~08 완전한 구문, kc-09~16 단어·조각뿐, kc-17~24 정상 이벤트). 정상 이벤트를 `block`한 경우 0건. `npm run xdr:respond:cve` → 거부 규칙 7개(근거 경보 8건), 다시 흘리기: 명확한 공격 막힘 8/8 · 애매한 시도 0 · 정상 이벤트 0 |
| 시험 | `node --test test/xdr-known-cve.test.mjs`(로컬 시험 경보, 심판 판정 아님) |

## 12단계 탈환 작전실 요약 (서비스·경로)

| 항목 | 내용 |
|---|---|
| 서비스 | `notes` 자료실 화면 안의 「탈환 작전실」 패널 |
| 경로 | `GET /api/ops`(요약), `GET /api/ops?requestId=<UUID>`(요청 기록 한 줄). 구현 `api/ops.js`, `src/ops-service.mjs`. 로그인 필요(비로그인 `401`), 브라우저 로그인은 승인된 기기 쿠키도 필요(아니면 `403`). `GET` 외 메서드는 `405` |
| 화면 | 기기가 서버에서 `approved`로 확인된 뒤에만 열리고(`checkDevice` 한 곳), `/api/ops` 응답의 값과 서버가 붙인 라벨만 `textContent`로 그립니다. 메모 제목·내용은 읽지도 표시하지도 않습니다 |
| 라벨 | `확인됨(서버 기록)` = 서버가 남긴 가린 요청 기록·기기 표·복원 감사·사본 표를 읽은 값 / `코드에서 읽음` = 규칙·경로 표·정책 지문을 코드에서 읽은 값(실행 결과 아님) / `미실행` = 이 서버가 볼 수 없거나 아직 실행하지 않은 것 / `확인하지 못함` = 읽으려 했지만 읽지 못함 |
| 판정기 규칙 | `RULE_IDS`와 경로 표(`ROUTE_TABLE`)는 **코드에서 읽음**. 엔진·심판이 `decide()`를 부른 실제 판정 결과는 **미실행**(이 서버는 볼 수 없음) |
| 탐지 사건 | 규칙(`burst_read`, 10분 120건 초과)은 코드에서 읽음. 서버 기록에서는 **GET 줄 수만 셉니다**(전체 = 로그인 사용자 + 비로그인, 사용자 수, 10분 안 가장 많은 줄 수). `detect()` 결과나 회수 제안은 **계산해 채우지 않습니다.** 탐지 판단·회수 제안은 엔진 몫이라 **미실행** |
| 회수 상태 | 기기 승인 표의 대기·승인·해제·그 밖 줄 수(합계 포함)는 확인됨(서버 기록). 회수 제안과 접속 회수 집행·걸린 시간은 운영 엔진 몫이라 **미실행**(제안 건수를 우리 쪽에서 만들지 않음) |
| 복구 버전 | 정책 사본 버전·지문 앞 12자(코드에서 읽음), 메모 사본 표 줄 수, 복원 감사 줄 수(계획·시작·완료·거부·실패·추적·그 밖, **추적 줄 포함 표 전체**) |
| 요청 기록 | 새 표 `defense_ops_log`(`supabase/step12-ops.sql`): 번호·시각·요청 ID·메서드·경로 이름(`notes/:id` 형태)·상태·거부 이유 코드·인증 방식·사용자 가명(해시 12자)·점검 이름(`X-Attack-Id` 헤더가 있을 때만)만. 사용자 ID 원문·이메일·토큰·쿠키·다른 헤더·User-Agent·본문·메모 제목·내용·쿼리는 저장하지 않습니다(진단용으로 잠시 남겼던 User-Agent·헤더 이름·쿼리 칸은 코드에서 빼고 DB 값도 2026-10-14에 모두 비웠습니다. 줄 수는 그대로). 최근 2000건만 남는 순환 기록이고, 응답을 보내기 **전에** 기록합니다. 기록이 실패해도 원래 응답은 바뀌지 않습니다(그 요청은 표에도 화면에도 없음) |
| 화면 수치 = 서버 기록 | 요청 기록 수치는 **기록 표 전체**(24시간 같은 자르기 없음)를 맨 끝 번호까지 한 시점에서 읽은 줄 수입니다. 그래서 `select count(*) from defense_ops_log`(그 번호까지)와 같고, `전체 = 허용 + 거부 + 오류 = 경로별 합계`입니다(`test/ops-api.test.mjs`가 검산, 읽는 동안 새 줄이 들어오는 경우 포함). 화면의 번호(`id`)로 표의 줄을 찾을 수 있고, 요청 ID는 앞 8자만 보입니다. 자기 점검(`npm run bundle`의 `src/attack-check.mjs`)이 `X-Attack-Id`로 붙인 **점검 이름은 가리지 않고** 기록 표의 「점검 이름」 열과 「점검 이름별 기록」(이름마다 줄 수와 가장 최근 번호·경로·상태)에 보여 줍니다. 그래서 제출 묶음의 `attackId`로 가린 서버 기록의 해당 요청을 찾아 결과를 대조할 수 있습니다. 정적 파일(`/`, `/data.json`, `/manifest.webmanifest`)과 원본 저장소(Supabase) 직접 요청은 이 서버를 거치지 않아 기록에 없습니다. 표에 **없는 요청**은 화면에도 없습니다: `/api/auth/*`, 정적 파일(화면에 그렇게 적어 둠) |
| 41종 | 아직 실행하지 않았고 이 저장소에 41종 목록도 없습니다. 화면과 표 모두 `미실행` 한 줄이며 통과로 표시하지 않습니다 |
| SQL | `supabase/step12-ops.sql`(① 표·권한·순환 규칙 ② 확인). **직접 실행해야 합니다.** 실행 전에는 요청 기록 묶음이 `확인하지 못함`이고 기록은 조용히 건너뜁니다(자료 API 응답은 그대로) |

### 1~12단계 정상·금지 요청 한 표 (`npm run ops:table`)

`scripts/ops-table.mjs` + `src/ops-checks.mjs`가 배포 주소(`publicAppUrl`)로 **실제 요청**을 보내 한 표를 만듭니다: 단계 · 정상/금지 · 기대 결과 · 실제 API 결과(HTTP 상태와 거부 이유) · 요청 ID · 확인 시각 · 서버 기록 대조. 요청마다 `X-Request-Id`(UUID)를 붙이고, 응답 뒤 `GET /api/ops?requestId=`로 서버 기록의 상태가 응답과 같은지 다시 봅니다(`일치`/`불일치`/`기록 없음`/`확인 못함`). 허용된 요청과 거부된 요청이 모두 측정 결과로 남습니다.

- 계정 환경변수가 없으면 비로그인·가짜 토큰 줄만 보내고 나머지는 `미실행`과 이유를 적습니다. 값은 셸에서만 넣고 저장·출력하지 않습니다: `ALEPH_OPS_EMAIL_A`, `ALEPH_OPS_PASSWORD_A`, `ALEPH_OPS_EMAIL_B`, `ALEPH_OPS_PASSWORD_B`.
- A는 가상 메모 한 건을 만들었다가 마지막에 지웁니다. B가 그 메모를 읽기·수정·삭제하려는 요청은 거부되어야 합니다.
- 5단계 원본 직접 조회(공개 키만 쓰는 GET, 기대: `401`·`403` 또는 빈 목록), 10단계 비로그인 복원 요청(`401`), 11단계 A가 본문에 `{"status":"approved"}`를 보내는 기기 요청(`400`, 상태 변화 없음)도 이 표가 실제로 보냅니다(2026-10-14 추가, 아래 두 번째 실행에서 배포로 실행함). 원본 직접 조회는 우리 서버를 거치지 않아 서버 기록 대조는 `해당 없음`입니다.
- 6·7·9단계(판정·재판정·탐지·회수)와 41종 총공세는 운영 엔진·심판이 보내므로 이 표에서는 항상 `미실행`입니다.
- 결과는 `artifacts/ops-table.json`(Git에 올라가지 않음)과 화면의 표로 나옵니다. 불일치가 하나라도 있으면 종료 코드가 1입니다.
- **실제 배포로 실행함 (2026-10-14 00:34~00:35 KST, 커밋 `065af45`, 학생 PC에서 시험 계정 A·B로 실행):** 23줄 중 **일치 18 · 불일치 0 · 미실행 5**. 결과 파일 `artifacts/ops-table.json`은 Git에 올리지 않았습니다.
  - 정상 요청 허용(실측): A 메모 목록 `200`, 가상 메모 추가 `201`, 읽기 `200`, 수정 `200`, 삭제(정리) `204`, 공지 목록 `200`, 기기 상태(직접 호출) `200`, 작전실 요약 `200`.
  - 금지 요청 거부(실측): 비로그인 메모 목록 `401`, 서명 없는 가짜 토큰 `401`, B가 A의 메모 읽기·수정·삭제 `403`, 일반 학생의 공지 수정 `403`, A가 B 소유로 복원 미리보기 `403`, 비로그인 기기 상태 `401`, 비로그인 작전실 요약 `401`, 정적 `/data.json`은 `200`이지만 메모 없음.
  - 서버 기록 대조: 서버 기록 대상인 17줄 모두 `일치`(응답 상태 = 서버가 남긴 가린 기록의 상태). 정적 `/data.json` 1줄은 기록 대상이 아니라 `해당 없음`.
  - 미실행 5줄: 5단계 원본 직접 조회, 6·7단계 판정, 9단계 탐지·회수, 41종 총공세(이 표가 보내지 않음, 통과로 표시하지 않음).
  - **두 번째 실행 (2026-10-14 01:28~01:29 KST, 커밋 `a091a70`):** 25줄 중 **일치 21 · 불일치 0 · 미실행 4**. 새로 넣은 3줄도 실측: 공개 키로 원본 저장소 직접 조회 `401`(메모 없음), 비로그인 복원 요청 `401`, A가 본문에 `{"status":"approved"}`를 보내는 기기 요청 `400 INVALID_DEVICE_REQUEST`(실행 뒤 DB의 기기 표는 6줄 그대로, 가장 최근 요청·승인 시각도 실행 전 값이라 상태가 바뀌지 않음을 확인). 서버 기록 대상 19줄 모두 `일치`, 우리 서버를 거치지 않는 2줄(`/data.json`, 원본 직접 조회)은 `해당 없음`. 점검용 메모는 마지막에 지워져 남지 않음(0건). 미실행 4줄은 6·7·9단계와 41종(운영 엔진·심판 몫).
  - 같은 날 앞선 실행 두 번은 중간에 끊겨 점검용 가상 메모 2건이 A 계정에 남았습니다(제목 `ops-table 점검용…`). 2026-10-14 01:15 KST에 학생이 SQL Editor에서 그 제목의 메모만 지워 **정리함**(남은 0건, 메모 8 → 6건). 사본 트리거가 지우기 직전 값을 남겨 사본 표는 11 → 12줄(같은 내용은 한 번만 남김).

### 제출 묶음의 점검 결과(`attackAttempts`)는 모두 `not_run`

- 제출 묶음의 `observed`는 **심판이 그 `attackId`로 직접 실행하고 기록한 공격의 결과**를 적는 칸입니다. 심판 결과 「실행 기록 대조」가 "그 attackId로 보낸 요청 기록이 없습니다(요청을 보내지 않은 점검은 observed를 not_run으로 적습니다)"라고 알려 준 것처럼, 학생 자기 점검이 보낸 공개 GET은 그 기록이 아닙니다.
- 그래서 12단계 `npm run bundle`(`src/attack-check.mjs`)은 **요청을 보내지 않고** 19개 점검을 모두 `observed: "not_run"`으로 적습니다. 실패했다는 뜻이 아니라 이 묶음에는 심판이 기록한 실행이 없다는 뜻이며, 통과로 주장하지 않습니다(41종도 `not_run`).
- 같은 정상·금지 요청의 **실제 결과**(HTTP 상태, 요청 ID, 확인 시각, 서버 기록 대조)는 `npm run ops:table`로 배포에 직접 보내 위 「1~12단계 정상·금지 요청 한 표」에 기록했습니다(2026-10-14, 일치 21 · 불일치 0 · 미실행 4).
- 11단계까지의 자기 점검(배포에 비로그인·가짜 토큰 GET을 보내 관측값을 적던 동작)은 코드와 시험(`test/r5.test.mjs`)에 그대로 남아 있습니다.

### 설치·실행·중지·복구 (이 README가 들어 있는 커밋 기준)

확인할 커밋은 저장소 최신 커밋(`git rev-parse HEAD`)이고, 배포된 커밋은 `/aleph.json`의 `commit`으로 대조합니다.

| 단계 | 방법 |
|---|---|
| 설치 | `git clone <repoUrl>` → `npm ci`(Node 22 이상). Vercel에 이 저장소를 새 프로젝트로 연결 |
| 환경변수(이름만) | Vercel: `SUPABASE_URL`, `SUPABASE_SECRET_KEY`(서버 전용), 선택 `INSTRUCTOR_USER_IDS`. 값은 Vercel의 비밀 입력란에만 넣고 코드·Git·화면에 쓰지 않습니다 |
| 자료 표 준비 | Supabase SQL Editor에서 `supabase/` 의 SQL을 단계 순서대로 블록 단위로 검토 후 실행: `step2` → `step3` → `step4` → `step8` → `step10-backup` → `step10-backup-trigger` → `step11-devices` → `step12-ops` |
| 실행 | 배포 주소를 열고 로그인 → 「이 기기의 승인 상태」에서 「승인 요청」 → 운영 측이 `defense_devices`에서 승인 → 「상태 새로 확인」 → 자료실과 「탈환 작전실」이 열림 |
| 시험(로컬, 배포 증명 아님) | `npm run test:ops && npm run test:device && npm run test:restore && npm run test:decider && npm run test:detect && npm run test:step2 && npm run test:r5 && npm run test:package` |
| 점검 | `npm run ops:table`(위 표), `npm run bundle`(자기 점검, 제출 묶음) |
| 중지 | 즉시 막기: Vercel에서 프로젝트를 일시중지하거나 `SUPABASE_SECRET_KEY`를 끄면 자료 API가 열리지 않습니다. 사용자 접속: Supabase에서 해당 계정 로그아웃/비활성화, 기기: `update public.defense_devices set status = 'revoked', decided_at = now() where id = '<deviceId>';` |
| 복구 | 메모 한 건: `POST /api/restore`(미리보기 → `ownerId`+`contentSha256` 확인 후 `dryRun:false`), 정책: `npm run policy:diff` → `npm run policy:restore`. 코드: 문제 커밋만 `git revert <sha>`(`git reset --hard`는 쓰지 않음). 복구 뒤 `npm run ops:table`로 정상·금지 요청을 다시 확인 |

### 누가 만든 것인가 (ALEPH SDP 엔진 사용)

| 구분 | 내용 |
|---|---|
| ALEPH SDP 엔진 사용 | 운영 반 엔진(요청 전달·판정기 호출·탐지 사건 전달·접속 회수 집행)과 심판 접수 서버(`judgeIssuer`), 시작 틀(`scripts/bundle.mjs`, `scripts/build-public.mjs`, `scripts/deployment-identity.mjs`, `docs/`, `package/` 양식, `xdr/`). 이 저장소는 그 엔진을 포함하거나 대신하지 않고, 엔진의 동작 결과도 만들지 않습니다 |
| 학생이 만든 것 | 자료 API(`api/*`, `src/notes-service.mjs`, `src/zones.mjs`, `src/auth-service.mjs`), 판정기 규칙(`src/decider.mjs`), 탐지 규칙(`src/detect.mjs`), 복구(`src/restore-service.mjs`, `src/policy-restore.mjs`), 접속 앱·기기 승인(`public/`, `src/device-*.mjs`), 작전실(`src/ops-*.mjs`, `public/index.html`), 자기 점검(`src/attack-check.mjs`), SQL(`supabase/`), 시험(`test/`) |
| 엔진에 맡긴 것(미확인) | 판정기·탐지 함수가 엔진에서 실제로 불리는지, 회수 제안이 접속 차단으로 이어지는지, 걸린 시간은 이 저장소에서 확인하지 못했습니다 |

### 처음부터 다시 만드는 순서
1~2단계 가상 메모 비공개와 로그인 없는 `/data.json` 점검 → 3·4단계 로그인과 본인 메모만 읽기·쓰기(`step2~4` SQL) → 5단계 원본 직접 조회 차단(`step5` SQL은 제안, 적용 여부는 직접 확인) → 6·7단계 `src/decider.mjs` → 8단계 구역(`step8` SQL) → 9단계 `src/detect.mjs` → 10단계 사본·복구(`step10` SQL 둘) → 11단계 접속 앱·기기 승인(`step11` SQL) → 12단계 작전실(`step12` SQL) → `npm run ops:table` → `npm run bundle`.

### 12단계에 남은 약점
- 판정기·탐지·회수의 **실제 결과는 엔진·심판이 만들며** 이 서버는 볼 수 없어 작전실에 `미실행`으로 남깁니다. 탐지 칸은 우리 서버가 본 GET 줄 수일 뿐 엔진이 전달한 사건이나 그 판단이 아닙니다.
- 요청 기록은 순환 표(최근 2000건)라서 추가만 가능한 감사 로그가 아닙니다. 서버 기록 대조(`ops:table`)는 그 안에 있는 요청만 확인합니다. 기록 저장이 실패한 요청은 응답은 나갔어도 표와 화면에 없습니다.
- Bearer로 직접 부르는 요청은 기기 승인을 확인하지 않습니다(11단계와 같음). 기기 쿠키는 하드웨어에 묶인 키가 아닙니다.
- `/api/ops`는 판정기 구역 표에 없고 `allowedRoutes`에도 넣지 않았습니다(`/api/device`와 같은 취급).
- 판정기 소유 기록의 규칙 충돌(무인증 조회 → 타인 메모 조회 순서)은 "다툼 중 경로는 추가 확인"으로 보완했습니다(`test/decider.test.mjs`, 로컬 가상 요청, 심판 판정 아님). 무인증 요청 없이 다른 사용자가 바로 먼저 오는 경우는 판정기 계약에 주인 값이 없어 여전히 판정기만으로는 막지 못하고, 자료 API가 `403 owner_mismatch`로 막습니다(배포에서 실측).
- 이 단계의 배포 확인 (2026-10-14):
  - `supabase/step12-ops.sql` 적용: **실행함**(DB에서 `defense_ops_log` 표와 기록 줄을 읽어 확인).
  - 작전실 화면: **실행함**. 새 브라우저에서 승인 요청 → 운영 측 승인 → 「상태 새로 확인」 뒤 작전실이 열렸고(학생이 확인), 시크릿 창의 비로그인 `/api/ops`는 오류만 나왔습니다(`ops:table`에서도 `401`).
  - `npm run ops:table`: **실행함**(위 기록).
  - 작전실 화면 숫자 = 가린 서버 기록: **실행함**(2026-10-14 01:01 KST, 배포 커밋 `e379b70`). 학생이 작전실 캡처(기록 번호 1~283)를 보냈고, 같은 번호 범위를 DB에서 직접 세어 모두 같았습니다.
    - 요청 기록: 전체 283 = 허용 109 + 거부 174 + 오류 0. 경로별 device 74 · notes 90 · notes/:id 18 · notices 18 · notices/:id 5 · ops 64 · restore 14(허용·거부까지 같음).
    - 탐지(GET 줄): 263 = 로그인 사용자 99 + 비로그인 164, 사용자(가명) 2명.
    - 기기 승인 표: 대기 1 · 승인 5 · 해제 0(합계 6). 메모 사본 11줄. 복원 감사: 계획 2 · 시작 2 · 완료 2 · 거부 6 · 실패 0 · 추적 21(합계 33).
    - 판정 결과·탐지 판단·회수 제안·집행·41종은 화면에 `미실행`으로 나왔고 숫자를 채우지 않았습니다. 메모 제목·내용은 화면에 없었습니다.

## 11단계 접속 앱·기기 승인 요약 (서비스·경로)

| 항목 | 내용 |
|---|---|
| 서비스 | `notes` 자료실 화면(설치형 웹앱) |
| 앱 설정 | `public/manifest.webmanifest`(앱 이름 「BYTE BACK 자료실」, `standalone`, 아이콘 3개), `public/offline.html`(오프라인 안내), `public/sw.js`(최소 서비스 워커) |
| 기기 승인 경로 | `GET /api/device`(상태 조회), `POST /api/device`(승인 요청). 구현 `api/device.js`, `src/device-service.mjs` |
| 부르는 사람 | 서버가 검증한 로그인 사용자만(비로그인은 `401`) |
| 상태 | `none`(요청 전) → `pending`(대기) → `approved`(승인) / `revoked`(해제). 승인·해제는 **운영 측이 DB(`defense_devices`)에서만** 바꿉니다. 화면 버튼·요청 본문·쿼리·헤더로는 승인되지 않고, 본문에 `status` 같은 값을 보내면 `400`입니다 |
| 브라우저에 두는 것 | 서버가 준 읽을 수 없는(`HttpOnly`·`Secure`·`SameSite=Strict`) 쿠키 `__Host-aleph-dv` 하나(서버가 만든 무작위 핸들). DB에는 그 SHA-256 지문만 저장하고 핸들 원문은 응답·로그·DB 어디에도 없습니다. 기기 키·토큰·승인 상태를 `localStorage` 등에 넣지 않습니다 |
| 승인 전 화면 | 로그인해도 승인 전(`none`·`pending`·`revoked`·확인 실패)에는 자료 영역을 숨기고 `/api/notes`를 부르지 않습니다. 서버가 `approved`라고 답한 뒤에만 기존 자료실을 엽니다 |
| 서버의 기기 확인 | 화면만이 아니라 **서버가 직접** 확인합니다(`src/device-gate.mjs`). 브라우저 로그인(쿠키)으로 오는 `/api/notes`·`/api/notes/:id`·`/api/notices` 요청은 같은 브라우저의 기기 쿠키가 가리키는 행이 **이 사용자의 `approved`**일 때만 통과하고, 아니면 자료 표를 읽기 전에 `403 DEVICE_NOT_APPROVED`(`X-Deny-Reason: device_not_approved`)입니다. 승인 여부를 DB에서 읽지 못하면 `503`으로 닫습니다. `Authorization` 헤더(Bearer)로 직접 오는 요청은 기존 로그인·소유자 확인 그대로입니다(기기 확인을 더하지 않음) |
| 자료실을 여는 조건 | **서버가 확인한 승인 결과뿐입니다.** 화면에서 자료실을 여는 곳은 `checkDevice` 한 곳이고, `GET /api/device`가 이번에 `approved`라고 답했을 때만 엽니다. 「승인 요청」 버튼은 `POST /api/device`로 요청만 보내고, 그 응답이 무엇이든 열지 않고 `GET`으로 서버에 다시 물어봅니다. 앱 설치 여부·서비스 워커·`beforeinstallprompt` 같은 설치 이벤트는 열림 조건에 쓰지 않습니다 |
| 서비스 워커 | 인터넷이 끊겼을 때 오프라인 안내만 보여 줍니다. `/api/*`와 `/aleph.json`은 가로채지도 보관하지도 않습니다 |
| SQL | `supabase/step11-devices.sql`(① 표 만들기 ② 확인, 승인·해제 문장은 주석). **실행함**: 표 `defense_devices` 생성, RLS 켜짐, `anon`·`authenticated` 권한 모두 `false`, 0행임을 DB에서 읽어 확인했습니다 |
| 운영 측 승인 방법 | SQL Editor에서 `select id, owner_id, status, requested_at from public.defense_devices order by requested_at desc;`로 확인한 뒤 `update public.defense_devices set status = 'approved', decided_at = now() where id = '<deviceId>';` |
| 판정기 | `src/decider.mjs`는 바꾸지 않았습니다. 계약(`docs/DECIDER_REQUEST.md`)에 기기 승인 값이 없고 `request.device.approval`을 만들어 쓰지 않습니다. `RULE_IDS`도 그대로입니다 |
| 한계 | 이 승인 상태는 **앱 화면이 자료를 열지 말지 정하는 표시**이고, 운영 엔진의 기기 등록(`deviceRegistered`)과 판정을 대신하지 않습니다. 기존 보호 API의 로그인·소유자·구역 확인은 그대로이고, 거기에 **브라우저 로그인 요청에 한해** 승인된 기기 쿠키 확인을 더했습니다(Bearer 직접 호출은 바꾸지 않아서, 토큰만 가진 호출까지 기기로 막지는 못합니다. 그 부분은 운영 엔진의 기기 등록이 맡습니다). 쿠키 핸들은 기기 하드웨어에 묶인 키가 아니라서, 쿠키가 통째로 복사되면 같은 기기로 보일 수 있습니다. `/api/device`는 판정기 구역 표에 없어서(기본 거부) 엔진을 거치는 경로로 허용되려면 운영 측 규칙이 별도로 필요하며, `allowedRoutes`에는 넣지 않았습니다 |

**11단계 다시 실행하는 방법**
- 로컬 시험(배포 증명 아님): `npm run test:device`(기기 승인 API 7개 + 서버 기기 확인 5개 + 앱 설정·서비스 워커·가짜 화면 10개). 가짜 화면 시험은 실제 `public/index.html` 코드를 가짜 DOM으로 실행해, 승인 전(`none`·`pending`·`revoked`)과 확인 실패·모르는 값에서는 `/api/notes`를 부르지 않고 `approved`에서만 부르는지 봅니다.
- 배포 확인(승인 요청 → 승인 → 열림은 실행함. 아래 거부 요청 세 가지도 2026-10-14에 배포에서 실행함: 승인 전 콘솔 `403 DEVICE_NOT_APPROVED`, 비로그인 `401`, 본문 `status` `400`): ① 운영 주소에서 로그인 → 「이 기기의 승인 상태」가 `아직 승인을 요청하지 않았습니다`이고 자료가 보이지 않아야 합니다. ② 「승인 요청」 → `승인 대기 중`이고 자료는 계속 없어야 합니다. ③ 운영 측이 위 `update`로 승인 → 「상태 새로 확인」 → `승인된 기기`와 기존 자료실이 열려야 합니다. 거부되어야 할 것: 승인 전 브라우저 콘솔에서 `fetch('/api/notes')`는 `403 DEVICE_NOT_APPROVED`(자료 없음), 비로그인 `GET /api/device`는 `401`, 본문에 `{"status":"approved"}`를 보내는 `POST /api/device`는 `400`이고 상태가 바뀌지 않습니다.

- 실제 실행에서 「승인 요청」을 두 번 눌러 같은 기기에 대기 행이 둘 생긴 일이 있어, 요청이 끝나기 전에는 버튼을 잠그도록 고쳤습니다(이미 생긴 대기 행 1개는 남아 있고, 한 사용자의 대기·승인 기기 상한 5대에 포함됩니다).

## 10단계 「백업에서 자료실을 되살립니다」 기록 (통과함)

## 10단계 복구 경로 요약 (서비스·경로)

| 항목 | 내용 |
|---|---|
| 서비스 | `notes` (가상 메모 자료실) |
| 복구 경로 | `POST /api/restore` (`aleph.config.json`의 `restoreRoute`, 공개 `/aleph.json`의 `restoreRoute`와 같은 값) |
| 구현 파일 | `api/restore.js`, `src/restore-service.mjs` |
| 부르는 사람 | 서버가 검증한 로그인 사용자(`Authorization: Bearer <토큰>` 또는 로그인 쿠키). 사본의 주인 본인, 또는 서버에 등록된 강사(다른 사람의 메모일 때 `ownerId` 필요) |
| 요청 본문 | `{ "id": "<메모 UUID>", "ownerId"?, "contentSha256"?, "dryRun"? }` — `id`만 필수(`noteId`도 같은 뜻). 다른 값(`role`, 내용 등)은 `400` |
| 실행 전 미리보기 | 기본 동작입니다. 쓰지 않고 복원할 **사본 버전**(`backup.id`, `takenAt`, `verified`)과 **바뀔 항목**(`changes.title`·`content`·`create`, `willWrite`), 실제 복원에 보낼 확인값(`confirm`)만 돌려줍니다. 제목·내용은 담지 않습니다 |
| 실제 복원 | `dryRun: false` **그리고** `ownerId`와 `contentSha256`을 모두 보냈을 때만 합니다. 하나라도 없으면 `400 confirmation_required`로 쓰지 않습니다 |
| 사본 | 비공개 표 `defense_notes_backup`(서버만 읽음). 한 건만 다시 읽어 ID·소유자·내용 해시를 요청과 대조하고, 저장된 해시를 내용에서 다시 계산해 모두 맞을 때만 복원하며 하나라도 다르면 쓰지 않고 멈춥니다. 감사 기록(started)을 남긴 뒤 **쓰기 직전에 사본을 한 번 더 읽어 다시 검증**하고, 달라졌으면 쓰지 않습니다(409). 정책 CLI도 쓰기 직전에 사본 파일을 다시 읽어 해시를 다시 맞추고, 해시 목록과 별개로 코드에 고정한 기대 해시(`PINNED_SHA256`)와도 대조합니다 |
| 성공 | 미리보기 `200 { applied: false, dryRun: true, … }`, 복원 `200 { applied: true, restored: true, created: false\|true, id, ownerId, contentSha256 }` (메모 제목·내용은 응답에 없음) |
| 거부 | 로그인 없음 `401`, 형식 오류·확인값 없음 `400`, 남의 메모 `403 not_owner`, 사본 없음·해시 다름 `404`, 사본 검증 실패 `409`(쓰지 않음), 공지 번호·소유자가 다른 자리 `403` |
| 보존 | 대상 한 건 외의 메모는 읽지도 쓰지도 지우지도 않고, 감사 표 `defense_restore_audit`은 덧붙이기만 합니다 |
| 해시 규칙 | `sha256(UTF-8(title) + 0x00 + UTF-8(content))` 소문자 16진수 |
| 정책 사본 | `npm run policy:diff`(차이만 보기), `npm run policy:restore`(보여 주기, `--apply --confirm <해시 12자>`일 때만 적용). 실제 운영 정책은 건드리지 않음 |

**10단계에서 더한 기능**

- **정책 사본 차이 보기**: `npm run policy:diff`는 침해 전에 검증한 안전 정책 사본(`policy/verified/policy-v1.json`, 해시 목록 `policy/verified/MANIFEST.json`)과 현재 시험 정책(`policy/test-policy.json`)의 차이만 보여 줍니다. 사본이 없거나 해시 목록과 다르거나 형식이 틀리면 중단하고 아무것도 쓰지 않습니다. 사본 해시(SHA-256)는 `364f5a32af39e6d2a8b3730cc5a2aef0d206fafe3c0fb8e4068c8902b29aaf0f`입니다. 출력의 앞 12자와 이 값이 같은지 확인하세요.
- **정책 되돌리기**: `npm run policy:restore`는 복원할 버전·해시·바뀔 항목을 보여 주기만 하고, `npm run policy:restore -- --apply --confirm <해시 앞 12자>`일 때만 대상 서비스(`notes`) 하나를 사본으로 바꿉니다. 다른 서비스 규칙은 사본과 달라도 그대로 두고, 감사 이력(`audit`)은 지우지 않고 한 줄을 더합니다. 실제 운영 정책(`src/decider.mjs`, 반 엔진 설정)은 읽지도 바꾸지도 않는 시험용 사본입니다.
- **메모 한 건 복원 경로**: 서비스 `notes`, 경로 `POST /api/restore`(`api/restore.js`, `src/restore-service.mjs`), `aleph.config.json`의 `restoreRoute`에 같은 값을 적었고, 10단계부터 공개 `/aleph.json`에도 `restoreRoute`가 함께 실립니다(심판이 복구 요청을 보낼 주소). 본문은 `{ "id": "<메모 UUID>", "ownerId"?: "<주인 UUID>", "contentSha256"?: "<내용 해시 64자>", "dryRun"?: true|false }`이고 `id`(또는 `noteId`)만 필수입니다. **기본은 미리보기**라서 복원할 사본 버전과 바뀔 항목, 확인값을 보여 주기만 하고 쓰지 않습니다. 실제 복원은 `dryRun: false`에 `ownerId`·`contentSha256`을 모두 보냈을 때만 하고, 둘 중 하나라도 없으면 `400 confirmation_required`입니다. 소유자 권한은 서버가 검증한 로그인에서 오며 본문 값으로 생기지 않습니다. 다른 값(`role`, 내용 등)은 400입니다. 서버는 비공개 사본 표 `defense_notes_backup`에서 그 소유자의 그 한 건만 읽어 ID·소유자(와 보낸 해시)가 같은지, 저장된 해시가 내용에서 다시 계산한 값과 같은지 대조하고, 하나라도 다르면 쓰지 않습니다(404/409). 다른 사람의 메모를 복원하려면 사본의 주인 본인이거나 `INSTRUCTOR_USER_IDS`의 강사가 `ownerId`를 적어야 하고, 아니면 사본을 읽기 전에 `403 not_owner`입니다. 지금 자료실에 같은 번호가 있으면 개인 메모 구역이고 소유자가 같을 때만 제목·내용을 사본 값으로 바꾸고, 없으면 사본의 ID·소유자·위치로 한 건을 만듭니다. 다른 메모와 공지는 읽지도 쓰지도 지우지도 않습니다. `dryRun: true`는 쓰지 않고 대상과 현재 상태(`liveExists`, `liveMatchesCopy`)만 돌려줍니다. 응답에는 메모 제목·내용이 없습니다.
- **감사 기록**: 쓰기 전에 `defense_restore_audit`에 `started`를 남기고(못 남기면 쓰지 않고 503), 끝나면 `restored`/`failed`를 더합니다. 이 표는 덧붙이기만 되고 서버 키로도 고치거나 지울 수 없게 DB 트리거로 막았습니다(SQL을 적용한 뒤).
- **요청 흔적**: `POST /api/restore`가 받은 요청마다 감사 표에 `outcome = 'trace'` 한 줄(`m=메서드;s=응답 상태;a=인증 방식;k=본문 키 이름`)을 남깁니다. 값·토큰·메모 내용·사용자 ID는 담지 않고 서버 한 개당 100줄까지만 남깁니다. 복구 요청이 실제로 어떤 모양으로 왔는지 확인하려는 진단용입니다.
- **내용 해시 규칙**: `sha256(UTF-8(title) + 0x00 + UTF-8(content))` 소문자 16진수. SQL과 서버가 같은 규칙을 씁니다.

**10단계 실행 순서 (SQL은 직접 검토하고 실행합니다)**

1. `supabase/step10-backup.sql`을 ①→②→③→④ 블록으로 나눠 하나씩 Run 합니다. ③이 지금의 개인 메모를 사전 백업으로 복사하고, ④가 사본을 다시 읽어 `ok_rows`가 `total`과 같은지, 두 표의 `anon`/`authenticated` 권한이 모두 `false`인지 보여 줍니다. 침해 **전**의 정상 상태에서 실행해야 의미가 있습니다.
   - (보강) `supabase/step10-backup-trigger.sql`을 ① → ② 순서로 Run 하면, 이후 메모를 만들거나 고치거나 지우기 **직전의 값**이 `defense_notes_backup`에 자동으로 한 건씩 쌓입니다(같은 값은 한 번만). 그래서 나중에 만든 메모도 변조 전 값으로 복원할 수 있습니다. 사본을 남기지 못해도 메모 쓰기는 막지 않고 경고만 남기며, 앱 코드는 바꾸지 않습니다. 되돌리려면 파일 맨 아래 `drop trigger` 줄만 실행합니다. **실행함**: 트리거 2개(`defense_notes_snapshot_insert`, `defense_notes_snapshot_change`)가 켜져 있고(`enabled O`, 보안 정의자) 기존 사본 5건은 그대로임을 DB에서 읽어 확인했습니다. 실제 메모 변경으로 사본이 쌓이는 것은 **미실행**입니다.
2. 복원 대상의 `id`(필요하면 `ownerId`·`contentSha256`도)는 시험 계정 B의 메모에 대해 SQL Editor에서 `select note_id, owner_id, content_sha256 from public.defense_notes_backup where owner_id = '<B의 사용자 UUID>';`로 확인합니다(메모 본문은 보지 않아도 됩니다).
3. 먼저 `{ id }`만(또는 `dryRun: true`) 보내 미리보기를 보고, 응답의 `confirm` 값을 그대로 붙여 `dryRun: false`로 다시 보냅니다. 호출 예(로그인 쿠키가 있는 브라우저 콘솔): `fetch('/api/restore', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id:'<UUID>', ownerId:'<B UUID>', contentSha256:'<해시>', dryRun:true})}).then(r => r.json()).then(console.log)`
   - 정상: B 계정으로 로그인한 상태에서 B의 메모만 `200`, 응답의 세 값이 요청과 같습니다.
   - 거부: A 계정으로 B의 메모를 요청하면 `403 not_owner`, 해시를 바꾸면 `404`, 로그인이 없으면 `401`.
4. 시험: `npm run test:restore`(복원 16건·정책 5건, 가짜 DB·임시 폴더). 실제 DB·배포·심판 판정을 증명하지 않습니다.

**복구 뒤 1~11단계 재확인 순서 (실행한 것만 상태에 적음)**

복구 직후 아래 순서로 확인하고, 실제로 실행한 것만 결과를 적습니다.

| 순서 | 확인 | 정상(허용) | 금지(거부) | 상태 |
|---|---|---|---|---|
| 1 | `npm run policy:diff` | 차이 없음 | 사본 없음·해시 불일치면 중단 | 로컬 실행함(차이 없음) |
| 2 | 로컬 시험 모음(`test:decider`, `test:step2`, `test:r5`, `test:package`, `test:detect`, `test:restore`, `decider:test`, `detect:test`) | 전부 통과 | — | 로컬 실행함 |
| 3 | 1~3단계: 첫 화면·`/data.json` | 화면이 뜸 | `/data.json`에 메모 없음 | 배포에서 실행함(2026-10-14 `ops:table`: `/data.json` `200`, 메모 없음) |
| 4 | 3~4단계: A 로그인 후 자기 메모 읽기·추가·수정·삭제 | `200`·`201` | 로그인 없는 `/api/notes`는 `401`, 가짜 토큰 `401` | 배포에서 실행함(2026-10-14 `ops:table`: 목록 `200`·추가 `201`·읽기 `200`·수정 `200`·삭제 `204`, 비로그인 `401`, 가짜 토큰 `401`) |
| 5 | 4단계: B가 A의 메모 번호를 `GET`·`PUT`·`DELETE` | — | 모두 `403`(`X-Deny-Reason: owner_mismatch`) | 배포에서 실행함(2026-10-14 `ops:table`: `GET`·`PUT`·`DELETE` 모두 `403`) |
| 6 | 5단계: 공개 키로 원본 API 직접 요청 | — | `401`/`403`/빈 목록 | 배포에서 실행함(2026-10-14 `ops:table`: 공개 키만으로 직접 조회 `401`, 메모 없음) |
| 7 | 6~7단계: 미등록 기기·이상 접속 요청 | 정상 요청 허용 | `device_not_registered` 거부, 복합 이상은 `step_up` | 실제 판정은 **미실행**(운영 엔진·심판이 보냄). 가상 연습 `npm run decider:test`는 2026-10-14 실행함: 4개 모두 통과(등록 기기 정상, 미등록 기기, 복합 이상 접속, 다시 확인한 복합 이상 접속). **심판 판정 아님** |
| 8 | 8단계: 공지 목록·일반 학생의 공지 수정 | 공지 목록 `200` | 공지 수정 `403 instructor_required` | 배포에서 실행함(2026-10-14 `ops:table`: 공지 목록 `200`, 일반 학생의 공지 수정 `403`) |
| 9 | 9단계: 정상 기기·폭주 조회 사건 | 정상은 `observe` | 10분 120건 초과는 `propose_revocation` | 실제 사건 전달·회수는 **미실행**(운영 엔진이 함). 가상 연습 `npm run detect:test`는 2026-10-14 실행함: 6개 모두 통과(정상 30건, 10분 안 120건·121건, 폭주 200건, 서로 다른 사용자 각 100건, 10분 밖 200건). **실제 회수·심판 판정 아님** |
| 10 | 10단계: B의 메모 한 건 복원 | `200`, 세 값 일치 | A의 요청 `403`, 해시 불일치 `404`/`409` | 정상 복원은 배포에서 실행함(아래 기록). 해시 불일치는 배포에서 B로 틀린 해시를 보내 `404 backup_not_found`(쓰기 없음)를 확인함. A가 B의 메모를 복원하려는 요청은 배포에서 `403 not_owner`로 거부됨을 확인함. 로그인 없는 복원 요청 `401`은 2026-10-14 `ops:table`에서 배포로 실행함 |
| 11 | 11단계: 승인 전 기기·승인된 기기 | 승인된 기기에서 기존 자료실이 열림 | 승인 전에는 자료 영역이 숨겨지고 `/api/notes`를 부르지 않음, 비로그인 `/api/device`는 `401` | 가짜 DB·가짜 화면 시험은 실행함. 배포에서는 승인 요청 → 대기 → 운영 측 `update`로 승인 → 기존 자료실 열림을 실제로 실행했고(DB에서 `approved`와 승인 시각 기록을 읽어 확인, 화면 열림은 사용자가 확인했다고 알려 옴), 비로그인 `GET /api/device` `401`은 2026-10-14 `ops:table`에서 실행함. 본문 `status` 거부 `400`(상태 변화 없음)도 2026-10-14 `ops:table`에서 실행함. 승인 전 기기의 자료 거부도 2026-10-14 01:37 KST 배포에서 실행함: 새 시크릿 창에서 A로 로그인하고 승인 요청은 하지 않은 상태로 `fetch('/api/notes')` → `403 DEVICE_NOT_APPROVED`(메모 없음) |

**10단계 실제 실행 기록 (2026-10-13, 배포 db506d8, 직접 실행한 것만)**

- `supabase/step10-backup.sql`의 ②~④를 학생이 Supabase에서 적용했고, ④에서 `anon`·`authenticated` 권한 네 값이 모두 `false`였습니다. 적용 뒤 Supabase에서 읽어 `defense_notes_backup` 5행(주인 있는 개인 메모 5건), `defense_restore_audit` RLS 켜짐을 확인했습니다. ④의 `total`/`ok_rows` 숫자는 학생에게서 받지 못했지만, 아래 해시 대조에서 5건 모두 사본 해시와 같았습니다.
- 시험 계정 B(사용자 ID `04495177…`, 메모 `ee6f1bd8…` 한 건)로 로그인해 `POST /api/restore`를 호출했습니다. `dryRun`은 `200`(`liveExists: true`; 출력이 잘려 `liveMatchesCopy` 값은 기록하지 못함), 실제 복원은 `200 {restored: true, created: false}`이고 응답의 ID·소유자·내용 해시가 사본과 같았습니다.
- 복원 뒤 DB 읽기: 5건 모두 현재 내용 해시가 사본 해시와 같고(`true`), 메모는 6행(개인 메모 5 + 공지 1)·사본 5행 그대로이며, 감사 표에는 `planned`, `started`, `restored`, `started`, `restored` 5줄이 순서대로 쌓였습니다(실제 복원 호출이 두 번 기록됨). 감사 기록은 한 줄도 줄지 않았습니다.
- 복원 전에 메모를 일부러 바꿔 보지 않았습니다. 그래서 이 실행은 "바뀐 메모가 되돌아왔다"가 아니라 "사본 값과 같은 상태가 확인됐다"까지만 증명합니다.
- 이 기록을 쓸 때(10단계) 배포에서 실행하지 않았던 것: A 계정이 B의 메모를 복원하려는 요청의 `403`, 해시를 바꾼 요청의 `404`, 로그인 없는 `401`, 위 표의 3~9번. 이 중 3·4·5·6·8번과 복원의 로그인 없는 `401`은 2026-10-14 `ops:table`로 실행했고, 7·9번(심판·운영 엔진 몫)은 아직 **미실행**입니다.

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
- 판정기 `src/decider.mjs`(`RULE_IDS`: `device_registered`, `zone_access`, `step_up_required`)에 구역 규칙 `zone_access`가 있습니다. 엔진이 확인한 `service`·`method`·`path`·`route`가 구역 표의 한 줄과 정확히 맞을 때만 통과합니다. 표는 프롬프트가 요구한 세 규칙, 즉 자기 메모 읽기(`GET /notes/:id`)·수정(`PUT /notes/:id`)과 강사 공지 수정(`PUT /notices/:id`, 허용하지 않음)뿐이며, 메모 목록·추가·삭제도 판정기 표에는 없습니다(자료 API는 그대로 처리합니다). 그 밖에 표에 없는 경로·메서드와 `route`의 불일치·쿼리가 붙은 요청(`queryLength` ≠ 0)·`:id` 자리의 `export` 같은 기능 이름·더 깊은 경로는 `deny`와 `zone_not_allowed`입니다. 자료는 쿼리가 아니라 경로의 ID 한 칸으로만 고르고, 그 ID는 UUID이거나 7단계 엔진 예시의 `demo`(자기 메모의 정상 요청)일 때만 인정하고, 그 밖의 이름(`other-1`, `learner_…`, `notice…` 등)은 모두 `deny`·`zone_not_allowed`입니다. 요청 계약에 소유자 값이 없어서, 판정기는 허용한 메모 경로를 처음 쓴 사용자(`subjectId`)를 소유 기록(프로세스 메모리, 최대 5000건)에 남기고 같은 경로를 다른 사용자가 요청하면 `deny`·`zone_not_allowed`로 거부합니다. 먼저 접근한 쪽이 주인이 되는 방식이고 서버가 다시 뜨면 기록이 사라지므로 최종 소유자 확인은 자료 API가 합니다. **12단계 보완:** 이 방식은 총공세처럼 무인증 조회 뒤 다른 사용자가 먼저 오면 그 사람이 주인이 되고 진짜 주인이 거부되는 충돌이 있었습니다(로컬에서 재현). 그래서 주인이 아직 없는 메모 경로에 무인증 요청(`subjectId` 없음)이 들어오면 그 경로를 10분 동안 "다툼 중"으로 표시하고, 그동안은 누가 요청해도 주인으로 기록하지 않고 `step_up`·`step_up_required`(7단계와 같은 결정·이유 코드)로 추가 확인을 요구합니다. 엔진이 새 로그인을 확인한 요청(`stepUp.verified`)만 허용하고 주인으로 기록합니다. 무인증 요청이 없는 흐름(A → B 거부, `/notes/demo` 정상 읽기)은 그대로입니다. 공지 읽기·수정(`GET·PUT /notices/:id`)은 요청 계약에 강사 역할 값이 없어 판정기가 허용하지 않습니다(공지 읽기는 자료 API가 로그인한 사용자에게 허용하지만 판정기 표에는 없습니다). 6단계 기기 규칙과 7단계 추가 확인 규칙은 그대로이고 순서는 기기 → 구역 → 추가 확인입니다.
- `aleph.config.json`: `step` 12, `restoreRoute` `POST /api/restore`. `allowedRoutes`는 구현한 메서드와 경로를 `GET /api/notes`처럼 한 줄씩 적습니다(`GET·POST /api/notes`, `GET·PUT·DELETE /api/notes/:id`, `GET /api/notices`, `GET·PUT /api/notices/:id`). 자기 점검에 구역 간 직접 요청(`cross_zone_direct_api`)과 9단계 탐지·회수(`doppelganger_burst_revocation`)를 미실행으로 기록합니다.

**다시 실행하는 방법 (SQL은 직접 검토하고 실행합니다)**

1. `supabase/step8-zones.sql`을 ①②③ 블록으로 나눠 Run 하면 `defense_notes`에 `zone` 열(`note`/`notice`)이 생기고 공개 가능한 가상 공지 한 건이 들어갑니다. 실행 전에는 서버가 모든 행을 개인 메모로 보므로 앱은 그대로 동작하고 공지 목록은 비어 있습니다.
2. 강사를 쓰려면 Vercel 환경변수 `INSTRUCTOR_USER_IDS`에 강사 계정의 사용자 UUID를 직접 넣고 재배포합니다. (비밀번호·키가 아니지만 코드와 Git에는 넣지 않습니다.)
3. 시험: `npm run test:decider && npm run test:step2 && npm run test:r5 && npm run test:package`, 그리고 `npm run decider:test` (가상 요청과 가짜 DB로 도는 시험이며 실제 DB·배포·심판 판정을 증명하지 않습니다.)
4. 직접 API 확인(예시, 로그인 후 쿠키 사용 또는 `Authorization` 헤더): B 계정으로 A 메모 번호를 `GET /api/notes/<번호>` 하면 `403`이고 자료가 없어야 합니다. 일반 학생이 `PUT /api/notices/<번호>` 하면 `403`(`X-Deny-Reason: instructor_required`)이어야 합니다. 본인 메모 읽기·수정은 그대로 `200`입니다.

### 이 단계에 남은 약점

- 10단계: 복원 경로는 사본 주인 본인도 부를 수 있어서, 계정 자체가 침해되면 그 계정이 자기 메모를 사본 값으로 되돌리는 것은 막지 못합니다(다른 사람의 메모는 못 건드립니다). 사본은 같은 Supabase 프로젝트의 비공개 표라서, DB 전체가 침해되면 사본도 함께 바뀔 수 있습니다. 정책 사본의 기대 해시는 이제 해시 목록(`MANIFEST.json`)과 별개로 `src/policy-restore.mjs`의 `PINNED_SHA256`에도 고정되어 있어서, 사본과 목록만 함께 바꾸면 중단합니다(새 버전을 인정하려면 사람이 그 상수를 고쳐야 합니다). 다만 저장소를 쓸 수 있는 사람이 코드까지 바꾸면 막지 못하고, `policy/test-policy.json`은 실제 운영 정책이 아니라 시험용 사본입니다. `POST /api/restore`는 판정기 구역 표에 없어서(기본 거부) 엔진을 거치는 경로로 허용되려면 운영 측 허용 규칙이 별도로 필요하고, `restoreRoute`의 표기 형식은 운영 계약으로 확인하지 못했습니다. `step10-backup.sql` 적용과 B의 메모 한 건 정상 복원은 실제로 실행했지만(위 기록), 거부 요청 중 틀린 해시의 `404`와 A의 `403 not_owner`는 배포에서 확인했지만, 로그인 없음 등 나머지 거부와 복원 전 변조 메모의 되돌림은 배포에서 확인하지 않았습니다.

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
