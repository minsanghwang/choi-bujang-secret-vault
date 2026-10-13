// 8단계: 강사 공지 목록. 로그인한 사용자만 읽을 수 있고, 수정은 /api/notices/:id에서 강사만 됩니다.
import { handleNoticeCollection } from '../src/notes-service.mjs';

export default function handler(request, response) {
  return handleNoticeCollection(request, response);
}
