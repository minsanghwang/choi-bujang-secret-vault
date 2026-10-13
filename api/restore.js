// 10단계: 비공개 사본에서 가상 메모 한 건 복원. POST만 받습니다. (서비스: notes)
import { handleRestore } from '../src/restore-service.mjs';

export default function handler(request, response) {
  return handleRestore(request, response);
}
