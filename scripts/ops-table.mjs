// 12단계: 1~12단계 정상·금지 요청을 실제로 보내 한 표(artifacts/ops-table.json + 화면 표)로 남깁니다.
// 실행:  npm run ops:table
// 로그인 계정이 있으면 더 많은 줄을 실행합니다. 값은 셸 환경변수로만 넣고(이 파일·Git·로그에 적지 않음) 출력하지 않습니다:
//   ALEPH_OPS_EMAIL_A / ALEPH_OPS_PASSWORD_A   (시험 계정 A)
//   ALEPH_OPS_EMAIL_B / ALEPH_OPS_PASSWORD_B   (시험 계정 B)
// 환경변수가 없으면 그 줄은 "미실행"으로 표시됩니다. 비로그인 요청은 계정 없이도 보냅니다.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runChecks, signIn, summarize, toMarkdown } from '../src/ops-checks.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const config = JSON.parse(await readFile(join(root, 'aleph.config.json'), 'utf8'));
const env = process.env;
const tokens = {};
const A = await signIn(config, env.ALEPH_OPS_EMAIL_A, env.ALEPH_OPS_PASSWORD_A);
const B = await signIn(config, env.ALEPH_OPS_EMAIL_B, env.ALEPH_OPS_PASSWORD_B);
if (A) tokens.A = A;
if (B) tokens.B = B;
console.log(`로그인: A ${A ? '성공' : '없음(미실행 처리)'} · B ${B ? '성공' : '없음(미실행 처리)'}`);

const rows = await runChecks({ config, tokens });
const commit = (await import('node:child_process')).execFileSync('git', ['rev-parse', '--short=12', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
const report = { schema: 'aleph.ops.table.v1', generatedAt: new Date().toISOString(), app: config.publicAppUrl, localCommit: commit,
  summary: summarize(rows), attacks41: { status: '미실행', note: '심판이 실행합니다. 이 표는 통과로 표시하지 않습니다.' }, rows };
await mkdir(join(root, 'artifacts'), { recursive: true });
await writeFile(join(root, 'artifacts', 'ops-table.json'), `${JSON.stringify(report, null, 2)}\n`);
console.log(toMarkdown(rows, { commit }));
console.log('\n저장: artifacts/ops-table.json (Git에 올라가지 않는 폴더)');
if (report.summary.mismatch > 0) process.exitCode = 1;
