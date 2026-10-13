// 3단계: GET 한 건·PUT 수정·DELETE 삭제. 소유자 검사는 4단계에서 붙입니다.
import { handleItem } from '../../src/notes-service.mjs';
import { withOpsLog } from '../../src/ops-log.mjs';

// 12단계: 응답 결과를 가려서 서버 기록에 남기는 감싸개(withOpsLog)로 감쌉니다. 응답 내용은 바뀌지 않습니다.
export default withOpsLog('notes/:id', (request, response) => handleItem(request, response));
