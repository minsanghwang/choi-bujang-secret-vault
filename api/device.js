// 11단계: 기기 승인 요청(POST)과 상태 조회(GET). 승인 결정은 이 파일이 아니라 운영 측이 서버 DB에서 합니다.
import { handleDevice } from '../src/device-service.mjs';
import { withOpsLog } from '../src/ops-log.mjs';

// 12단계: 응답 결과를 가려서 서버 기록에 남기는 감싸개(withOpsLog)로 감쌉니다. 응답 내용은 바뀌지 않습니다.
export default withOpsLog('device', (request, response) => handleDevice(request, response));
