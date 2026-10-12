// 2단계: 가상 메모를 코드 밖(Supabase 테이블)에서 서버 함수로 읽어 옵니다.
// SUPABASE_URL과 서버 전용 SUPABASE_SECRET_KEY는 Vercel 환경변수에서만 읽습니다.
// 키는 브라우저 파일·응답·로그에 넣지 않습니다.
// 알려진 약점: 이 함수는 아직 로그인 확인이 없어서 공개 주소로 누구나 부를 수 있습니다 (README 참고).
const TABLE = 'defense_notes';

function send(response, status, body) {
  response.setHeader('Cache-Control', 'no-store');
  response.status(status).json(body);
}

export default async function handler(request, response) {
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return send(response, 405, { error: 'METHOD_NOT_ALLOWED' });
  }
  const baseUrl = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  let endpoint;
  try {
    endpoint = new URL(`/rest/v1/${TABLE}`, baseUrl);
    if (endpoint.protocol !== 'https:' || !secretKey) throw new Error('config');
  } catch {
    return send(response, 500, { error: 'NOTES_NOT_CONFIGURED' });
  }
  endpoint.searchParams.set('select', 'title,content');
  endpoint.searchParams.set('order', 'position.asc');
  const headers = { apikey: secretKey, Accept: 'application/json' };
  // 예전 형식(JWT) 키는 Authorization도 필요하고, sb_secret_ 키는 apikey만 보냅니다.
  if (secretKey.startsWith('eyJ')) headers.Authorization = `Bearer ${secretKey}`;
  let rows;
  try {
    const upstream = await fetch(endpoint, { headers, signal: AbortSignal.timeout(8000) });
    if (!upstream.ok) {
      console.error('notes_upstream_status', upstream.status);
      return send(response, 502, { error: 'NOTES_UPSTREAM_ERROR' });
    }
    rows = await upstream.json();
  } catch {
    console.error('notes_upstream_failed');
    return send(response, 502, { error: 'NOTES_UPSTREAM_ERROR' });
  }
  if (!Array.isArray(rows)) return send(response, 502, { error: 'NOTES_UPSTREAM_ERROR' });
  // 화면에 필요한 두 칸만 돌려줍니다. id·owner_id는 내보내지 않습니다.
  return send(response, 200, {
    notes: rows.map(row => ({ title: String(row.title), content: String(row.content) })),
  });
}
