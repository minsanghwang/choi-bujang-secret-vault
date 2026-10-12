import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
// 2단계부터 가상 메모는 공개 파일이 아니라 서버 함수(api/notes.js)가 읽습니다.
// 그래서 data.json을 public으로 복사하지 않고, 공개 파일에 메모가 남아 있으면 빌드를 멈춥니다.
let publicData = null;
try {
  publicData = JSON.parse(await readFile(resolve(root, 'public', 'data.json'), 'utf8'));
} catch (error) {
  if (error.code !== 'ENOENT') throw new Error('public/data.json 형식을 확인하세요. 메모를 넣으면 안 됩니다.');
}
if (publicData && (!Array.isArray(publicData.notes) || publicData.notes.length > 0)) {
  throw new Error('public/data.json에 메모가 남아 있습니다. 메모는 공개 파일 밖(Supabase)에 두세요.');
}
await mkdir(resolve(root, 'public'), { recursive: true });
console.log('공개 파일에 가상 메모가 없는 것을 확인했습니다. data.json은 복사하지 않습니다.');
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
