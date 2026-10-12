// 3단계: GET 목록·POST 추가. 로그인 토큰은 서버가 src/verify-login.mjs로 검사합니다.
import { handleCollection } from '../src/notes-service.mjs';

export default function handler(request, response) {
  return handleCollection(request, response);
}
