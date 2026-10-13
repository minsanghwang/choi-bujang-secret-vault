// 8단계: 강사 공지 한 건. GET은 로그인한 사용자, PUT은 서버가 확인한 강사만 됩니다.
import { handleNoticeItem } from '../../src/notes-service.mjs';
import { withOpsLog } from '../../src/ops-log.mjs';

// 12단계: 응답 결과를 가려서 서버 기록에 남기는 감싸개(withOpsLog)로 감쌉니다. 응답 내용은 바뀌지 않습니다.
export default withOpsLog('notices/:id', (request, response) => handleNoticeItem(request, response));
