// 5단계 가점: /api/auth/login · /api/auth/logout · /api/auth/session. 로그인을 서버에서 처리합니다.
import { handleAuth } from '../../src/auth-service.mjs';

export default function handler(request, response) {
  return handleAuth(request, response);
}
