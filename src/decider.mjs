// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
// 6단계: 요청 계약(docs/DECIDER_REQUEST.md)에 있는 deviceRegistered만 봅니다.
export const RULE_IDS = Object.freeze(['device_registered']);

export async function decide(request) {
  // 값이 true일 때만 등록 기기로 봅니다. false·없음·문자열 "true" 등은 모두 미등록입니다.
  const registered = request?.deviceRegistered === true;
  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: registered ? 'allow' : 'deny',
    reasonCode: registered ? 'approved' : 'device_not_registered',
    ruleIds: ['device_registered'],
  };
}
