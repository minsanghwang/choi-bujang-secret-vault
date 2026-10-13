// 10단계: 비공개 사본에서 가상 메모 한 건 복원. POST만 받습니다. (서비스: notes)
import { handleRestore } from '../src/restore-service.mjs';
import { withOpsLog } from '../src/ops-log.mjs';

// 12단계: 응답 결과를 가려서 서버 기록에 남기는 감싸개(withOpsLog)로 감쌉니다. 응답 내용은 바뀌지 않습니다.
export default withOpsLog('restore', (request, response) => handleRestore(request, response));
