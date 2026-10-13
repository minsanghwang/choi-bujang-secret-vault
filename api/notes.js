// 3단계: GET 목록·POST 추가. 로그인 토큰은 서버가 src/verify-login.mjs로 검사합니다.
import { handleCollection } from '../src/notes-service.mjs';
import { withOpsLog } from '../src/ops-log.mjs';

// 12단계: 응답 결과를 가려서 서버 기록에 남기는 감싸개(withOpsLog)로 감쌉니다. 응답 내용은 바뀌지 않습니다.
export default withOpsLog('notes', (request, response) => handleCollection(request, response));
