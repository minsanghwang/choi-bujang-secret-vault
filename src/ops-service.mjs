// 12단계: 탈환 작전실이 읽는 요약.  GET /api/ops  (로그인 필요, 브라우저 로그인은 승인된 기기 쿠키도 필요)
//   GET /api/ops                  → 판정기 규칙·탐지·회수·복구·요청 기록 요약
//   GET /api/ops?requestId=<UUID> → 그 요청 ID의 서버 기록 한 줄(1~11단계 표 절차가 실제 결과를 대조할 때 씀)
// 모든 수치는 서버 기록(요청 기록·기기 표·복원 감사·사본 표)에서 읽은 줄 수이고, 화면은 이 응답의 값만 보여 줍니다.
// 각 묶음에는 라벨이 붙습니다: 확인됨(서버 기록) / 코드에서 읽음 / 미실행 / 확인하지 못함. 코드에서 읽은 규칙과 실제 실행 결과를 섞지 않습니다.
// 메모 제목·내용·사용자 ID·토큰은 읽지도 돌려주지도 않습니다(조회 항목에 title·content가 없음).
import { RULE_IDS, ROUTE_TABLE } from './decider.mjs';
import { detect } from './detect.mjs';
import { requireLogin } from './notes-service.mjs';
import { PINNED_SHA256 } from './policy-restore.mjs';

export const LABEL = Object.freeze({ observed: '확인됨(서버 기록)', code: '코드에서 읽음', notRun: '미실행', unknown: '확인하지 못함' });
const WINDOW_HOURS = 24;
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
const maskedRecord = row => ({ at: row.at, requestId: mask(row.request_id), method: row.method, route: row.route, status: row.status, reason: row.reason ?? null, auth: row.auth });
const classOf = status => (status >= 500 ? 'errors' : status >= 400 ? 'denied' : 'allowed');

// 같은 사용자의 GET이 10분 안에 가장 많았던 건수(참고 수치). 판정은 detect()가 합니다.
function busiestWindow(events) {
  const bySub = new Map();
  for (const event of events) { const t = Date.parse(event.at); if (Number.isFinite(t)) bySub.set(event.identity.sub, [...(bySub.get(event.identity.sub) ?? []), t]); }
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

function requestsBlock(rows) {
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
  return { label: LABEL.observed, windowHours: WINDOW_HOURS, truncated: rows.length >= ROW_LIMIT, total: rows.length, ...sums,
    byRoute: [...routes.values()].sort((a, b) => a.route.localeCompare(b.route)), records: rows.slice(0, RECORD_LIMIT).map(maskedRecord) };
}

function detectionBlock(rows) {
  const rule = { ...BURST, source: LABEL.code };
  const engineDelivery = { label: LABEL.notRun, note: '운영 엔진이 가상 사건을 detect()에 전달하고 회수를 집행하며, 우리 서버는 그 결과를 볼 수 없습니다.' };
  if (rows === null) return { rule, observed: { label: LABEL.unknown }, engineDelivery };
  const events = rows.filter(row => row.method === 'GET' && typeof row.actor === 'string')
    .map(row => ({ at: row.at, method: 'GET', identity: { sub: row.actor } }));
  const result = detect(events);
  return { rule, engineDelivery, observed: { label: LABEL.observed, windowHours: WINDOW_HOURS, getEvents: events.length,
    subjects: new Set(events.map(event => event.identity.sub)).size, busiestWindow: busiestWindow(events),
    result: { action: result.action, ...(result.reasonCode ? { reasonCode: result.reasonCode } : {}), ...(result.subject ? { subject: mask(result.subject).slice(0, 7) } : {}) } } };
}

const countBy = (rows, key, names) => Object.fromEntries(names.map(name => [name, rows.filter(row => row[key] === name).length]));

export async function buildSummary(deps = {}) {
  const since = new Date((deps.now?.() ?? Date.now()) - WINDOW_HOURS * 3600 * 1000).toISOString();
  const [log, devices, audit, backups] = await Promise.all([
    readOrNull('defense_ops_log', { select: 'at,request_id,method,route,status,reason,auth,actor', at: `gte.${since}`, order: 'at.desc', limit: String(ROW_LIMIT) }, deps),
    readOrNull('defense_devices', { select: 'status', limit: String(ROW_LIMIT) }, deps),
    readOrNull('defense_restore_audit', { select: 'outcome', outcome: 'neq.trace', limit: String(ROW_LIMIT) }, deps),
    readOrNull('defense_notes_backup', { select: 'note_id', limit: String(ROW_LIMIT) }, deps),
  ]);
  const detection = detectionBlock(log);
  const states = devices && countBy(devices, 'status', ['pending', 'approved', 'revoked']);
  const outcomes = audit && countBy(audit, 'outcome', ['planned', 'started', 'restored', 'denied', 'failed']);
  return {
    schema: 'aleph.ops.v1',
    generatedAt: new Date(deps.now?.() ?? Date.now()).toISOString(),
    commit: (process.env.VERCEL_GIT_COMMIT_SHA ?? '').slice(0, 12) || null,
    decider: { label: LABEL.code, ruleIds: [...RULE_IDS], routes: ROUTE_TABLE.map(item => ({ ...item })),
      realDecisions: { label: LABEL.notRun, note: '운영 엔진·심판이 decide()를 호출하며, 우리 서버는 그 판정 결과를 볼 수 없습니다.' } },
    detection,
    revocation: { devices: devices === null ? { label: LABEL.unknown } : { label: LABEL.observed, ...states, total: devices.length },
      proposals: { label: detection.observed.label, count: detection.observed.result?.action === 'propose_revocation' ? 1 : 0 },
      enforcement: { label: LABEL.notRun, note: '접속 회수의 집행과 걸린 시간은 운영 엔진이 정합니다. 우리 서버가 확인한 것은 기기 승인 상태뿐입니다.' } },
    recovery: { policy: { label: LABEL.code, version: Object.keys(PINNED_SHA256).at(-1), sha256Prefix: Object.values(PINNED_SHA256).at(-1).slice(0, 12) },
      backups: backups === null ? { label: LABEL.unknown } : { label: LABEL.observed, count: backups.length },
      restoreAudit: audit === null ? { label: LABEL.unknown } : { label: LABEL.observed, ...outcomes, total: audit.length } },
    requests: requestsBlock(log),
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
      const rows = await select('defense_ops_log', { select: 'at,request_id,method,route,status,reason,auth', request_id: `eq.${id.toLowerCase()}`, order: 'at.desc', limit: '1' }, deps);
      const row = rows[0];
      return json(response, 200, { schema: 'aleph.ops.record.v1', record: row ? { ...maskedRecord(row), requestId: row.request_id } : null });
    }
    return json(response, 200, await buildSummary(deps));
  } catch {
    console.error('ops_request_failed');
    return fail(response, 502, 'OPS_UPSTREAM_ERROR');
  }
}
