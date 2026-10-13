// 시험 정책(policy/test-policy.json)을 검증한 사본 버전으로 되돌립니다. 실제 운영 정책은 건드리지 않습니다.
//   node scripts/policy-restore.mjs                              → 바뀔 항목만 보여 주고 끝냅니다(쓰지 않음)
//   node scripts/policy-restore.mjs --apply --confirm <해시12자> → 보여 준 버전과 해시를 확인했을 때만 씁니다
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { applyRestore, describePlan, loadTestPolicy, loadVerified, planRestore, PolicyError, reloadVerified, writePolicy } from '../src/policy-restore.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const option = name => { const at = argv.indexOf(name); return at >= 0 ? argv[at + 1] : undefined; };
try {
  const verified = await loadVerified(root, option('--version') ?? null);
  const file = option('--test-policy') ? resolve(option('--test-policy')) : resolve(root, 'policy', 'test-policy.json');
  const current = await loadTestPolicy(root, file);
  const plan = planRestore(verified, current, option('--service') ?? undefined);
  process.stdout.write(`${describePlan(plan)}\n`);
  if (!argv.includes('--apply')) {
    process.stdout.write(`아직 아무것도 쓰지 않았습니다. 적용하려면: npm run policy:restore -- --apply --confirm ${plan.sha256.slice(0, 12)}\n`);
  } else if (option('--confirm') !== plan.sha256.slice(0, 12)) {
    throw new PolicyError('--confirm 값이 보여 준 사본 해시 앞 12자와 다릅니다. 적용하지 않았습니다.');
  } else if (!plan.willChange.length) {
    process.stdout.write('바뀔 항목이 없어 쓰지 않았습니다.\n');
  } else {
    const again = await reloadVerified(root, verified);   // 쓰기 직전에 사본을 다시 읽어 검증합니다. 실패하면 여기서 중단합니다.
    await writePolicy(file, applyRestore(again, current, plan));
    process.stdout.write(`${plan.service} 서비스를 ${plan.version}으로 되돌렸습니다. 다른 서비스와 감사 이력은 보존했습니다.\n`);
  }
} catch (error) {
  if (!(error instanceof PolicyError)) throw error;
  process.stderr.write(`정책 복원 중단: ${error.message}\n`);
  process.exitCode = 1;
}
