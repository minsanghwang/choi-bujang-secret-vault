// 11단계: 기기 승인 요청(POST)과 상태 조회(GET). 승인 결정은 이 파일이 아니라 운영 측이 서버 DB에서 합니다.
import { handleDevice } from '../src/device-service.mjs';

export default function handler(request, response) {
  return handleDevice(request, response);
}
