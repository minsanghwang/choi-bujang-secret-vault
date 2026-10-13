// 10단계: 침해 전에 검증한 안전 정책 사본과 현재 시험 정책을 견주고, 되돌릴 항목을 미리 보여 줍니다.
// 이 파일은 policy/ 아래 시험용 사본만 읽고 씁니다. 실제 운영 정책(src/decider.mjs, 반 엔진 설정)은 읽지도 바꾸지도 않습니다.
import { createHash } from 'node:crypto';
import { readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export const POLICY_SCHEMA = 'aleph.policy.v1';
export const DEFAULT_SERVICE = 'notes';
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const isObject = value => Boolean(value) && typeof value === 'object' && !Array.isArray(value);
const stable = value => JSON.stringify(value);

export class PolicyError extends Error {}
const stop = message => { throw new PolicyError(message); };

// 사본이 없거나, 해시 목록과 다르거나, 모양이 틀리면 PolicyError로 중단합니다. 정상값으로 채우지 않습니다.
export async function loadVerified(root, version = null) {
  let manifest;
  try { manifest = JSON.parse(await readFile(join(root, 'policy', 'verified', 'MANIFEST.json'), 'utf8')); } catch { stop('검증한 정책 사본의 해시 목록(MANIFEST.json)이 없거나 읽을 수 없습니다. 중단합니다.'); }
  if (manifest?.schema !== 'aleph.policy.manifest.v1' || !isObject(manifest.files)) stop('해시 목록 형식이 맞지 않습니다. 중단합니다.');
  const entries = Object.entries(manifest.files).filter(([, item]) => isObject(item) && (version === null || item.version === version));
  if (!entries.length) stop(version ? `검증한 정책 사본에 ${version} 버전이 없습니다. 중단합니다.` : '검증한 정책 사본이 목록에 없습니다. 중단합니다.');
  const [name, item] = entries.at(-1);
  if (!/^[A-Za-z0-9._-]+\.json$/u.test(name) || !/^[0-9a-f]{64}$/u.test(item.sha256 ?? '')) stop('해시 목록 항목이 맞지 않습니다. 중단합니다.');
  let bytes;
  try { bytes = await readFile(join(root, 'policy', 'verified', name)); } catch { stop(`검증한 정책 사본 ${name} 파일이 없습니다. 중단합니다.`); }
  if (sha256(bytes) !== item.sha256) stop('정책 사본의 해시가 목록과 다릅니다(검증 실패). 중단합니다.');
  let policy;
  try { policy = JSON.parse(bytes.toString('utf8')); } catch { stop('정책 사본이 JSON이 아닙니다. 중단합니다.'); }
  if (policy?.schema !== POLICY_SCHEMA || policy.version !== item.version || !isObject(policy.services)) stop('정책 사본의 형식이나 버전이 목록과 다릅니다. 중단합니다.');
  return { policy, version: item.version, sha256: item.sha256, file: name };
}

export async function loadTestPolicy(root, file = join(root, 'policy', 'test-policy.json')) {
  let policy;
  try { policy = JSON.parse(await readFile(file, 'utf8')); } catch { stop('현재 시험 정책을 읽을 수 없습니다. 중단합니다.'); }
  if (policy?.schema !== POLICY_SCHEMA || !isObject(policy.services) || !Array.isArray(policy.audit)) stop('현재 시험 정책의 형식이 맞지 않습니다. 중단합니다.');
  return policy;
}

// 값 단위로 펼쳐서 다른 곳만 돌려줍니다. 배열(규칙 목록)은 한 값으로 비교합니다. 감사 이력(audit)은 비교 대상이 아닙니다.
function flatten(node, prefix, out) {
  if (isObject(node)) for (const [key, value] of Object.entries(node)) flatten(value, prefix ? `${prefix}.${key}` : key, out);
  else out.set(prefix, stable(node));
  return out;
}
export function diffPolicy(verified, current, service = DEFAULT_SERVICE) {
  const a = flatten(verified.services, 'services', new Map());
  const b = flatten(current.services, 'services', new Map());
  const changes = [];
  for (const path of [...new Set([...a.keys(), ...b.keys()])].sort()) {
    if (a.get(path) === b.get(path)) continue;
    changes.push({ path, verified: a.get(path) ?? null, current: b.get(path) ?? null,
      kind: !b.has(path) ? 'removed' : !a.has(path) ? 'added' : 'changed',
      scope: path === `services.${service}` || path.startsWith(`services.${service}.`) ? 'restore' : 'keep' });
  }
  return changes;
}

// 되돌릴 계획. 대상 서비스 하나만 사본으로 바꾸고, 다른 서비스 규칙과 audit은 그대로 둡니다.
export function planRestore(verified, current, service = DEFAULT_SERVICE) {
  if (!isObject(verified.policy.services[service])) stop(`검증한 사본에 ${service} 서비스가 없습니다. 중단합니다.`);
  const changes = diffPolicy(verified.policy, current, service);
  return { service, version: verified.version, sha256: verified.sha256, changes,
    willChange: changes.filter(item => item.scope === 'restore'), willKeep: changes.filter(item => item.scope === 'keep') };
}
export function applyRestore(verified, current, plan, now = new Date()) {
  const next = structuredClone(current);
  next.services[plan.service] = structuredClone(verified.policy.services[plan.service]);
  next.audit = [...current.audit, { at: now.toISOString(), action: 'policy_restore', service: plan.service,
    version: plan.version, sha256: plan.sha256, changedPaths: plan.willChange.map(item => item.path) }];
  // 되돌린 뒤 대상 서비스는 사본과 같아야 하고, 다른 서비스와 이전 감사 이력은 그대로여야 합니다.
  const sameOthers = Object.keys(current.services).filter(key => key !== plan.service)
    .every(key => stable(next.services[key]) === stable(current.services[key]));
  if (!sameOthers || stable(next.audit.slice(0, current.audit.length)) !== stable(current.audit)
      || stable(next.services[plan.service]) !== stable(verified.policy.services[plan.service])) stop('되돌린 결과 검사가 맞지 않아 중단합니다.');
  return next;
}
export async function writePolicy(file, policy) {
  const temp = `${file}.tmp`;
  await writeFile(temp, `${JSON.stringify(policy, null, 2)}\n`, 'utf8');
  await rename(temp, file);
}

export function describePlan(plan) {
  const lines = [`복원할 안전 정책 버전: ${plan.version} (해시 ${plan.sha256.slice(0, 12)}…)`, `복원 대상 서비스: ${plan.service}`];
  const show = item => `  - ${item.path}: 현재 ${item.current ?? '(없음)'} → 사본 ${item.verified ?? '(없음)'}`;
  lines.push(plan.willChange.length ? `바뀔 항목 ${plan.willChange.length}개:` : '바뀔 항목 없음(현재 정책이 사본과 같습니다).', ...plan.willChange.map(show));
  if (plan.willKeep.length) lines.push(`다른 서비스에서 사본과 다르지만 건드리지 않는 항목 ${plan.willKeep.length}개:`, ...plan.willKeep.map(show));
  lines.push('감사 이력(audit)은 지우지 않고, 복원하면 한 줄을 더합니다.');
  return lines.join('\n');
}
