// 검증한 안전 정책 사본과 현재 시험 정책의 차이만 보여 줍니다. 파일을 쓰지 않습니다.
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describePlan, loadTestPolicy, loadVerified, planRestore, PolicyError } from '../src/policy-restore.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const option = name => { const at = argv.indexOf(name); return at >= 0 ? argv[at + 1] : undefined; };
try {
  const verified = await loadVerified(root, option('--version') ?? null);
  const current = await loadTestPolicy(root, option('--test-policy') ? resolve(option('--test-policy')) : undefined);
  process.stdout.write(`${describePlan(planRestore(verified, current, option('--service') ?? undefined))}\n(차이 보기만 했고 아무 파일도 바꾸지 않았습니다.)\n`);
} catch (error) {
  if (!(error instanceof PolicyError)) throw error;
  process.stderr.write(`정책 차이 보기 중단: ${error.message}\n`);
  process.exitCode = 1;
}
