// 11단계: 자료 API가 "서버가 승인한 기기"인지 직접 확인하는 곳입니다. 화면(JS)이 아니라 서버가 정합니다.
// 브라우저 로그인(쿠키)으로 오는 자료 요청은, 같은 브라우저의 기기 쿠키가 가리키는 행이 이 사용자의 approved일 때만 통과합니다.
// 승인 여부의 출처는 서버 DB(defense_devices)뿐이고, 설치 여부·요청 본문·헤더·쿼리는 읽지 않습니다.
import { createHash } from 'node:crypto';
import { readCookies } from './auth-service.mjs';

export const DEVICE_COOKIE = '__Host-aleph-dv';
export const HANDLE = /^[A-Za-z0-9_-]{43}$/u;                 // 서버가 만든 무작위 32바이트(base64url)
export const sha256 = text => createHash('sha256').update(text, 'utf8').digest('hex');

// 이 브라우저의 기기 핸들 지문 + 로그인한 사용자 + 상태 approved가 모두 맞는 행이 있으면 true.
// DB를 읽지 못하면 예외를 던지고, 호출한 쪽이 요청을 닫습니다(승인으로 가정하지 않습니다).
export async function deviceApproved(request, userId, deps = {}) {
  const handle = readCookies(request.headers?.cookie)[DEVICE_COOKIE];
  if (typeof handle !== 'string' || !HANDLE.test(handle)) return false;
  const key = process.env.SUPABASE_SECRET_KEY;
  const url = new URL('/rest/v1/defense_devices', process.env.SUPABASE_URL);
  if (url.protocol !== 'https:' || !key) throw new Error('config');
  url.searchParams.set('select', 'id');
  url.searchParams.set('handle_sha256', `eq.${sha256(handle)}`);
  url.searchParams.set('owner_id', `eq.${userId}`);
  url.searchParams.set('status', 'eq.approved');
  url.searchParams.set('limit', '1');
  const headers = { apikey: key, Accept: 'application/json' };
  if (key.startsWith('eyJ')) headers.Authorization = `Bearer ${key}`;
  const upstream = await (deps.fetch ?? fetch)(url, { method: 'GET', headers, signal: AbortSignal.timeout(8000) });
  if (!upstream.ok) throw new Error('device_lookup_failed');
  const rows = await upstream.json();
  return Array.isArray(rows) && rows.length === 1;
}
