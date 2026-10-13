// 8단계: 강사 공지 한 건. GET은 로그인한 사용자, PUT은 서버가 확인한 강사만 됩니다.
import { handleNoticeItem } from '../../src/notes-service.mjs';

export default function handler(request, response) {
  return handleNoticeItem(request, response);
}
