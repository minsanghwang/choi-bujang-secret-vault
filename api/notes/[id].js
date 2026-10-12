// 3단계: GET 한 건·PUT 수정·DELETE 삭제. 소유자 검사는 4단계에서 붙입니다.
import { handleItem } from '../../src/notes-service.mjs';

export default function handler(request, response) {
  return handleItem(request, response);
}
