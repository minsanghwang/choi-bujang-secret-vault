// 8단계: 자료실을 구역으로 나눕니다. 구역마다 자원 ID를 따로 표시하고, 같은 곳에서 접근 여부를 판단합니다.
//   note   = 학생 개인 메모(주인만)         → 주소 /api/notes, /api/notes/:id
//   notice = 강사 공지(읽기는 로그인한 학생, 수정은 강사만) → 주소 /api/notices/:id
// 판단 근거는 서버가 검증한 사용자 ID, DB에 저장된 행의 구역·owner_id, 서버 설정의 강사 목록뿐입니다.
// 화면 메뉴, 요청 본문의 role·owner_id·userId·zone은 읽지 않습니다.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export const ZONES = Object.freeze({ NOTE: 'note', NOTICE: 'notice' });

// 구역 열이 없는 옛 행·옛 DB는 모두 개인 메모로 봅니다. 알 수 없는 값은 null(거부)입니다.
export function zoneOf(row) {
  if (row?.zone === undefined || row?.zone === null) return ZONES.NOTE;
  return Object.values(ZONES).includes(row.zone) ? row.zone : null;
}
export const resourceId = (zone, id) => `${zone}:${String(id).toLowerCase()}`;

// 강사 목록은 Vercel 환경변수 INSTRUCTOR_USER_IDS(쉼표로 구분한 사용자 UUID)에서만 읽습니다. 비어 있으면 강사가 없습니다.
export function instructorIds(env = process.env) {
  return new Set(String(env.INSTRUCTOR_USER_IDS ?? '').split(',').map(item => item.trim().toLowerCase())
    .filter(item => UUID.test(item)));
}

// 접근 판단. route는 요청이 들어온 주소의 구역, action은 read | write | delete 입니다.
export function authorize({ route, action, row, userId, env = process.env }) {
  const zone = zoneOf(row);
  if (!zone) return { allow: false, reason: 'unknown_zone' };
  if (zone !== route) return { allow: false, reason: 'wrong_zone' };
  const id = resourceId(zone, row.id);
  if (zone === ZONES.NOTE) {
    if (typeof row.owner_id !== 'string' || !row.owner_id) return { allow: false, reason: 'owner_missing' };
    return row.owner_id.toLowerCase() === String(userId).toLowerCase()
      ? { allow: true, resourceId: id } : { allow: false, reason: 'owner_mismatch' };
  }
  if (action === 'read') return { allow: true, resourceId: id };
  return instructorIds(env).has(String(userId).toLowerCase())
    ? { allow: true, resourceId: id } : { allow: false, reason: 'instructor_required' };
}
