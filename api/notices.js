// 8단계: 강사 공지 목록. 로그인한 사용자만 읽을 수 있고, 수정은 /api/notices/:id에서 강사만 됩니다.
import { handleNoticeCollection } from '../src/notes-service.mjs';
import { withOpsLog } from '../src/ops-log.mjs';

// 12단계: 응답 결과를 가려서 서버 기록에 남기는 감싸개(withOpsLog)로 감쌉니다. 응답 내용은 바뀌지 않습니다.
export default withOpsLog('notices', (request, response) => handleNoticeCollection(request, response));
