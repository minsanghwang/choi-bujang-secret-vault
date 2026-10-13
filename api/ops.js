// 12단계: 탈환 작전실이 읽는 요약. 자기 자신은 요청 기록에 남기지 않습니다(기록이 기록을 부풀리지 않게).
import { handleOps } from '../src/ops-service.mjs';

export default function handler(request, response) {
  return handleOps(request, response);
}
