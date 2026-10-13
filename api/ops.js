// 12단계: 탈환 작전실이 읽는 요약. 다른 경로처럼 가린 요청 기록(withOpsLog)에 남깁니다(심판·화면이 이 경로를 불렀는지 서버 기록으로 볼 수 있게).
// 요약 수치는 응답을 보내기 전에 정한 기록 표의 맨 끝 번호까지만 세므로, 이 요청 자신의 줄은 다음 요약부터 들어갑니다.
import { handleOps } from '../src/ops-service.mjs';
import { withOpsLog } from '../src/ops-log.mjs';

export default withOpsLog('ops', (request, response) => handleOps(request, response));
