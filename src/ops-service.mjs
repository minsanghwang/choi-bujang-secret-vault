// 12단계: 탈환 작전실이 읽는 요약.  GET /api/ops  (로그인 필요, 브라우저 로그인은 승인된 기기 쿠키도 필요)
//   GET /api/ops                  → 판정기 규칙·탐지·회수·복구·요청 기록 요약
//   GET /api/ops?requestId=<UUID> → 그 요청 ID의 서버 기록 한 줄(1~11단계 표 절차가 실제 결과를 대조할 때 씀)
// 모든 수치는 서버 기록(요청 기록·기기 표·복원 감사·사본 표)에서 읽은 "줄 수"이고, 화면은 이 응답의 값만 보여 줍니다.
// 계산해서 채우는 결과는 없습니다: 판정·탐지 판단·회수 제안처럼 엔진이 내는 결과는 만들지 않고 미실행으로 둡니다.
// 요청 기록 수치는 기록 표 전체(최근 2000건 보관)를 한 시점(맨 끝 번호)에서 잘라 읽은 것이라, 표를 직접 세면 같은 값이 나옵니다.
// 각 묶음에는 라벨이 붙습니다: 확인됨(서버 기록) / 코드에서 읽음 / 미실행 / 확인하지 못함. 코드에서 읽은 규칙과 실제 실행 결과를 섞지 않습니다.
// 메모 제목·내용·사용자 ID·토큰은 읽지도 돌려주지도 않습니다(조회 항목에 title·content가 없음).
import { RULE_IDS, ROUTE_TABLE } from './decider.mjs';
import { requireLogin } from './notes-service.mjs';
import { PINNED_SHA256 } from './policy-restore.mjs';

export const LABEL = Object.freeze({ observed: '확인됨(서버 기록)', code: '코드에서 읽음', notRun: '미실행', unknown: '확인하지 못함' });
const LOG_LIMIT = 2100;              // 기록 표는 최근 2000건만 보관하므로 이보다 많이 읽을 일이 없습니다.
const ROW_LIMIT = 1000;
const RECORD_LIMIT = 30;
const BURST = Object.freeze({ reasonCode: 'burst_read', windowMinutes: 10, limit: 120 });
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

const json = (response, status, body) => { response.setHeader('Cache-Control', 'no-store'); response.status(status).json(body); };
const fail = (response, status, error) => json(response, status, { error });

async function select(table, query, deps) {
  const key = process.env.SUPABASE_SECRET_KEY;
  const url = new URL(`/rest/v1/${table}`, process.env.SUPABASE_URL);
  if (url.protocol !== 'https:' || !key) throw new Error('config');
  for (const [name, value] of Object.entries(query)) url.searchParams.set(name, value);
  const headers = { apikey: key, Accept: 'application/json' };
  if (key.startsWith('eyJ')) headers.Authorization = `Bearer ${key}`;
  const upstream = await (deps.fetch ?? fetch)(url, { method: 'GET', headers, signal: AbortSignal.timeout(8000) });
  if (!upstream.ok) throw new Error(`upstream_${upstream.status}`);
  const rows = await upstream.json();
  if (!Array.isArray(rows)) throw new Error('shape');
  return rows;
}
const readOrNull = async (table, query, deps) => { try { return await select(table, query, deps); } catch { return null; } };

const mask = id => `${String(id).slice(0, 8)}…`;
// 점검 이름(attackId)은 자기 점검이 X-Attack-Id로 붙인 이름이라 가리지 않고 그대로 보여 줍니다. 점검 결과와 서버 기록을 같은 이름으로 대조하는 데 씁니다.
const maskedRecord = row => ({ at: row.at, requestId: mask(row.request_id), method: row.method, route: row.route, status: row.status, reason: row.reason ?? null, auth: row.auth, attackId: row.attack_id ?? null });
const classOf = status => (status >= 500 ? 'errors' : status >= 400 ? 'denied' : 'allowed');

// 같은 사용자(가명)의 GET 줄이 10분 안에 가장 많았던 줄 수. 줄을 센 값이며 판정이 아닙니다.
function busiestWindow(rows) {
  const bySub = new Map();
  for (const row of rows) { const t = Date.parse(row.at); if (Number.isFinite(t)) bySub.set(row.actor, [...(bySub.get(row.actor) ?? []), t]); }
  let best = 0;
  for (const times of bySub.values()) {
    times.sort((a, b) => a - b);
    let start = 0;
    for (let end = 0; end < times.length; end += 1) {
      while (times[end] - times[start] >= BURST.windowMinutes * 60 * 1000) start += 1;
      best = Math.max(best, end - start + 1);
    }
  }
  return best;
}

// 기록 표에서 읽지 못하는 요청: 이 표에 없는 것은 화면 수치에도 없습니다.
const NOT_LOGGED = '기록 대상이 아닌 요청: /api/auth/*, 정적 파일. 기록 표는 최근 2000건만 보관합니다.';

// 점검 이름별 기록: 그 이름으로 남은 줄 수와 가장 최근 줄(번호·시각·경로·상태). 점검 결과(attackAttempts)의 이름으로 서버 기록을 찾을 수 있게 합니다.
function attackRows(rows) {
  const byName = new Map();
  for (const row of rows) {                       // rows는 최신 번호부터
    if (typeof row.attack_id !== 'string' || !row.attack_id) continue;
    const entry = byName.get(row.attack_id);
    if (entry) { entry.rows += 1; continue; }
    byName.set(row.attack_id, { attackId: row.attack_id, rows: 1, latest: { seq: row.id, at: row.at, method: row.method, route: row.route, status: row.status, requestId: mask(row.request_id) } });
  }
  return [...byName.values()].sort((a, b) => a.attackId.localeCompare(b.attackId));
}

function requestsBlock(rows, truncated) {
  if (rows === null) return { label: LABEL.unknown, note: '요청 기록 표(defense_ops_log)를 읽지 못했습니다. supabase/step12-ops.sql 적용 여부를 확인하세요.', total: null };
  const sums = { allowed: 0, denied: 0, errors: 0 };
  const routes = new Map();
  for (const row of rows) {
    const kind = classOf(row.status);
    sums[kind] += 1;
    const entry = routes.get(row.route) ?? { route: row.route, total: 0, allowed: 0, denied: 0, errors: 0 };
    entry.total += 1; entry[kind] += 1;
    routes.set(row.route, entry);
  }
  return { label: LABEL.observed, scope: '기록 표 전체(맨 끝 번호까지 한 시점에서 읽음)', note: NOT_LOGGED, truncated, total: rows.length, ...sums,
    newestSeq: rows[0]?.id ?? null, oldestSeq: rows.at(-1)?.id ?? null, newestAt: rows[0]?.at ?? null, oldestAt: rows.at(-1)?.at ?? null,
    byRoute: [...routes.values()].sort((a, b) => a.route.localeCompare(b.route)),
    byAttack: attackRows(rows),
    records: rows.slice(0, RECORD_LIMIT).map(row => ({ seq: row.id, ...maskedRecord(row) })) };
}

// 탐지: 규칙은 코드에서 읽은 값이고, 서버 기록에서는 GET 줄을 센 값만 보여 줍니다. detect() 결과·회수 제안은 계산해 채우지 않습니다.
function detectionBlock(rows) {
  const rule = { ...BURST, source: LABEL.code };
  const engine = { label: LABEL.notRun, note: '사건을 detect()에 전달하고 회수를 제안·집행하는 것은 운영 엔진입니다. 우리 서버는 그 결과를 볼 수 없어 만들지 않습니다.' };
  if (rows === null) return { rule, observed: { label: LABEL.unknown }, engineResult: engine, engineDelivery: engine };
  const gets = rows.filter(row => row.method === 'GET');
  const withActor = gets.filter(row => typeof row.actor === 'string');
  return { rule, engineResult: engine, engineDelivery: engine,
    observed: { label: LABEL.observed, scope: '기록 표 전체', getRows: gets.length, getRowsWithUser: withActor.length, getRowsWithoutUser: gets.length - withActor.length,
      users: new Set(withActor.map(row => row.actor)).size, busiestWindowRows: busiestWindow(withActor) } };
}

const countBy = (rows, key, names) => {
  const counts = Object.fromEntries(names.map(name => [name, rows.filter(row => row[key] === name).length]));
  return { ...counts, other: rows.length - Object.values(counts).reduce((a, b) => a + b, 0), total: rows.length };
};

export async function buildSummary(deps = {}) {
  // ① 기록 표의 맨 끝 번호를 먼저 정하고, ② 그 번호까지만 읽습니다. 읽는 동안 새 줄이 들어와도 합계와 줄 수가 어긋나지 않습니다.
  const head = await readOrNull('defense_ops_log', { select: 'id', order: 'id.desc', limit: '1' }, deps);
  const snapshot = head === null ? null : (head[0]?.id ?? 0);
  const [log, devices, audit, backups] = await Promise.all([
    snapshot === null ? null : readOrNull('defense_ops_log', { select: 'id,at,request_id,method,route,status,reason,auth,actor,attack_id', id: `lte.${snapshot}`, order: 'id.desc', limit: String(LOG_LIMIT) }, deps),
    readOrNull('defense_devices', { select: 'status', limit: String(ROW_LIMIT) }, deps),
    readOrNull('defense_restore_audit', { select: 'outcome', limit: String(ROW_LIMIT) }, deps),
    readOrNull('defense_notes_backup', { select: 'note_id', limit: String(ROW_LIMIT) }, deps),
  ]);
  const logTruncated = Array.isArray(log) && log.length >= LOG_LIMIT;
  const partial = rows => Array.isArray(rows) && rows.length >= ROW_LIMIT;
  const states = devices && countBy(devices, 'status', ['pending', 'approved', 'revoked']);
  const outcomes = audit && countBy(audit, 'outcome', ['planned', 'started', 'restored', 'denied', 'failed', 'trace']);
  const detection = detectionBlock(log);
  return {
    schema: 'aleph.ops.v1',
    generatedAt: new Date(deps.now?.() ?? Date.now()).toISOString(),
    commit: (process.env.VERCEL_GIT_COMMIT_SHA ?? '').slice(0, 12) || null,
    decider: { label: LABEL.code, ruleIds: [...RULE_IDS], routes: ROUTE_TABLE.map(item => ({ ...item })),
      realDecisions: { label: LABEL.notRun, note: '운영 엔진·심판이 decide()를 호출하며, 우리 서버는 그 판정 결과를 볼 수 없습니다.' } },
    detection,
    revocation: { devices: devices === null ? { label: LABEL.unknown } : { label: LABEL.observed, truncated: partial(devices), ...states },
      proposals: { label: LABEL.notRun, note: '회수 제안은 운영 엔진이 탐지 결과로 내며, 우리 서버는 제안 건수를 만들지 않습니다.' },
      enforcement: { label: LABEL.notRun, note: '접속 회수의 집행과 걸린 시간은 운영 엔진이 정합니다. 우리 서버가 확인한 것은 기기 승인 상태 줄 수뿐입니다.' } },
    recovery: { policy: { label: LABEL.code, version: Object.keys(PINNED_SHA256).at(-1), sha256Prefix: Object.values(PINNED_SHA256).at(-1).slice(0, 12) },
      backups: backups === null ? { label: LABEL.unknown } : { label: LABEL.observed, truncated: partial(backups), rows: backups.length },
      restoreAudit: audit === null ? { label: LABEL.unknown } : { label: LABEL.observed, truncated: partial(audit), ...outcomes } },
    requests: requestsBlock(log, logTruncated),
    unrun: { attacks41: { label: LABEL.notRun, note: '12단계 41종 공격 방어는 심판이 실행합니다. 이 화면은 그 결과를 표시하지 않으므로 아직 아무 결과도 없습니다.' } },
  };
}

export async function handleOps(request, response, deps = {}) {
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }
  const who = await requireLogin(request, response, deps, { requireDevice: true });
  if (!who) return undefined;
  try {
    const id = request.query?.requestId;
    if (id !== undefined) {
      if (typeof id !== 'string' || !UUID.test(id)) return fail(response, 400, 'INVALID_REQUEST_ID');
      const rows = await select('defense_ops_log', { select: 'at,request_id,method,route,status,reason,auth,attack_id', request_id: `eq.${id.toLowerCase()}`, order: 'at.desc', limit: '1' }, deps);
      const row = rows[0];
      return json(response, 200, { schema: 'aleph.ops.record.v1', record: row ? { ...maskedRecord(row), requestId: row.request_id } : null });
    }
    return json(response, 200, await buildSummary(deps));
  } catch {
    console.error('ops_request_failed');
    return fail(response, 502, 'OPS_UPSTREAM_ERROR');
  }
}
