// 10단계: 비공개 가상 메모 사본(defense_notes_backup)에서 지정한 한 건만 되살립니다.  POST /api/restore  (서비스: notes)
// 요청 본문: { id, ownerId, contentSha256, dryRun? } 세 값을 모두 사본과 대조하고, 다르면 쓰지 않습니다.
// 부르는 사람은 서버가 검증한 로그인 사용자뿐이며, 그 사람이 사본의 주인이거나 서버에 등록된 강사여야 합니다.
// 대상 한 건 외의 메모는 읽지도 쓰지도 않고, 지우지도 않습니다. 감사 기록(defense_restore_audit)은 덧붙이기만 합니다.
// 응답과 로그에는 메모 제목·내용·토큰을 담지 않습니다.
import { createHash } from 'node:crypto';
import { requireLogin } from './notes-service.mjs';
import { instructorIds, ZONES, zoneOf } from './zones.mjs';

const NOTES = 'defense_notes';
const BACKUP = 'defense_notes_backup';
const AUDIT = 'defense_restore_audit';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const HASH = /^[0-9a-f]{64}$/u;
const KEYS = new Set(['id', 'ownerId', 'contentSha256', 'dryRun']);

// 내용 해시 규칙(SQL과 같음): sha256( UTF-8(title) + 0x00 + UTF-8(content) ). 제목과 내용 사이 0x00은 글자에 들어갈 수 없는 값입니다.
export const noteHash = (title, content) => createHash('sha256')
  .update(Buffer.concat([Buffer.from(title, 'utf8'), Buffer.from([0]), Buffer.from(content, 'utf8')])).digest('hex');

const json = (response, status, body) => { response.setHeader('Cache-Control', 'no-store'); response.status(status).json(body); };
const fail = (response, status, error, reason) => {
  if (reason) response.setHeader('X-Deny-Reason', reason);
  return json(response, status, { error });
};

async function rest(table, method, query, payload, deps) {
  const key = process.env.SUPABASE_SECRET_KEY;
  const url = new URL(`/rest/v1/${table}`, process.env.SUPABASE_URL);
  if (url.protocol !== 'https:' || !key) throw new Error('config');
  for (const [name, value] of Object.entries(query)) url.searchParams.set(name, value);
  const headers = { apikey: key, Accept: 'application/json', Prefer: 'return=representation' };
  if (key.startsWith('eyJ')) headers.Authorization = `Bearer ${key}`;
  if (payload !== undefined) headers['Content-Type'] = 'application/json';
  const upstream = await (deps.fetch ?? fetch)(url, { method, headers, signal: AbortSignal.timeout(8000),
    body: payload === undefined ? undefined : JSON.stringify(payload) });
  let rows = null;
  try { rows = await upstream.json(); } catch { /* 본문 없음 */ }
  return { ok: upstream.ok, status: upstream.status, rows };
}

function readBody(request) {
  let body = request.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { return null; } }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  if (Object.keys(body).some(key => !KEYS.has(key))) return null;      // role·owner_id·content 같은 다른 값은 받지 않음
  if (typeof body.id !== 'string' || !UUID.test(body.id) || typeof body.ownerId !== 'string' || !UUID.test(body.ownerId)
      || typeof body.contentSha256 !== 'string' || !HASH.test(body.contentSha256)
      || (body.dryRun !== undefined && typeof body.dryRun !== 'boolean')) return null;
  return { id: body.id.toLowerCase(), ownerId: body.ownerId.toLowerCase(), hash: body.contentSha256, dryRun: body.dryRun === true };
}

// 감사 기록은 덧붙이기만 합니다. 실패해도 예외를 밖으로 내지 않고 성공 여부만 돌려줍니다.
async function audit(deps, actor, noteId, outcome, reason) {
  try {
    const result = await rest(AUDIT, 'POST', {}, { actor, note_id: noteId, outcome, reason: reason ?? null }, deps);
    return result.ok;
  } catch { return false; }
}

export async function handleRestore(request, response, deps = {}) {
  if (request.method !== 'POST') { response.setHeader('Allow', 'POST'); return fail(response, 405, 'METHOD_NOT_ALLOWED'); }
  const who = await requireLogin(request, response, deps);
  if (!who) return undefined;
  const wanted = readBody(request);
  if (!wanted) return fail(response, 400, 'INVALID_RESTORE_REQUEST');
  const caller = who.userId.toLowerCase();
  // 사본을 읽기 전에: 요청한 소유자 본인이거나 서버의 강사 목록에 있는 사람만 진행합니다.
  if (caller !== wanted.ownerId && !instructorIds().has(caller)) {
    await audit(deps, caller, wanted.id, 'denied', 'not_owner');
    return fail(response, 403, 'FORBIDDEN', 'not_owner');
  }
  try {
    const found = await rest(BACKUP, 'GET', {
      select: 'note_id,owner_id,position,title,content,note_created_at,content_sha256',
      note_id: `eq.${wanted.id}`, content_sha256: `eq.${wanted.hash}`, limit: '1' }, undefined, deps);
    if (!found.ok || !Array.isArray(found.rows)) return fail(response, 502, 'RESTORE_UPSTREAM_ERROR');
    const copy = found.rows[0];
    if (!copy) { await audit(deps, caller, wanted.id, 'denied', 'backup_not_found'); return fail(response, 404, 'BACKUP_NOT_FOUND', 'backup_not_found'); }
    // 사본을 다시 읽어 검증: ID·소유자·내용 해시가 요청과 같고, 저장된 해시가 내용에서 다시 계산한 값과 같아야 합니다.
    const intact = typeof copy.title === 'string' && typeof copy.content === 'string'
      && String(copy.note_id).toLowerCase() === wanted.id && String(copy.owner_id ?? '').toLowerCase() === wanted.ownerId
      && copy.content_sha256 === wanted.hash && noteHash(copy.title, copy.content) === wanted.hash;
    if (!intact) { await audit(deps, caller, wanted.id, 'denied', 'backup_mismatch'); return fail(response, 409, 'BACKUP_MISMATCH', 'backup_mismatch'); }

    // 지금 자료실에 같은 번호가 있으면 구역과 소유자를 확인합니다. 소유자를 바꾸거나 공지를 덮어쓰지 않습니다.
    let live = await rest(NOTES, 'GET', { select: 'id,owner_id,zone,title,content', id: `eq.${wanted.id}` }, undefined, deps);
    if (live.status === 400) live = await rest(NOTES, 'GET', { select: 'id,owner_id,title,content', id: `eq.${wanted.id}` }, undefined, deps);
    if (!live.ok || !Array.isArray(live.rows)) return fail(response, 502, 'RESTORE_UPSTREAM_ERROR');
    const current = live.rows[0];
    if (current) {
      if (zoneOf(current) !== ZONES.NOTE) { await audit(deps, caller, wanted.id, 'denied', 'wrong_zone'); return fail(response, 403, 'FORBIDDEN', 'wrong_zone'); }
      if (String(current.owner_id ?? '').toLowerCase() !== wanted.ownerId) { await audit(deps, caller, wanted.id, 'denied', 'owner_change'); return fail(response, 403, 'FORBIDDEN', 'owner_change'); }
    }
    const summary = { id: wanted.id, ownerId: wanted.ownerId, contentSha256: wanted.hash };
    if (wanted.dryRun) {
      const liveMatches = current ? noteHash(String(current.title), String(current.content)) === wanted.hash : false;
      await audit(deps, caller, wanted.id, 'planned', null);
      return json(response, 200, { dryRun: true, ...summary, liveExists: Boolean(current), liveMatchesCopy: liveMatches });
    }
    // 쓰기 전에 감사 기록을 먼저 남깁니다. 남기지 못하면 쓰지 않습니다.
    if (!await audit(deps, caller, wanted.id, 'started', null)) return fail(response, 503, 'AUDIT_UNAVAILABLE');
    const write = current
      ? await rest(NOTES, 'PATCH', { id: `eq.${wanted.id}`, owner_id: `eq.${wanted.ownerId}` }, { title: copy.title, content: copy.content }, deps)
      : await rest(NOTES, 'POST', {}, { id: wanted.id, owner_id: wanted.ownerId, title: copy.title, content: copy.content,
          ...(Number.isFinite(copy.position) ? { position: copy.position } : {}),
          ...(typeof copy.note_created_at === 'string' ? { created_at: copy.note_created_at } : {}) }, deps);
    const back = write.ok ? await rest(NOTES, 'GET', { select: 'title,content', id: `eq.${wanted.id}`, owner_id: `eq.${wanted.ownerId}` }, undefined, deps) : null;
    const row = back?.ok && Array.isArray(back.rows) ? back.rows[0] : null;
    if (!row || noteHash(String(row.title), String(row.content)) !== wanted.hash) {
      await audit(deps, caller, wanted.id, 'failed', 'readback_mismatch');
      return fail(response, 502, 'RESTORE_FAILED');
    }
    await audit(deps, caller, wanted.id, 'restored', current ? 'updated' : 'created');
    return json(response, 200, { restored: true, created: !current, ...summary });
  } catch {
    console.error('restore_request_failed');
    await audit(deps, caller, wanted.id, 'failed', 'upstream_error');
    return fail(response, 502, 'RESTORE_UPSTREAM_ERROR');
  }
}
