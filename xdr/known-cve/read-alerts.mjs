// 보너스 xdr-03 제작 1 · 경보 읽기 (확인용)
// xdr/fixtures/known-cve.json 의 Wazuh 경보에서 시각·출발 주소·계정·규칙 수준·설명만 뽑습니다.
// 원본 경보는 고치지 않고, 비밀값처럼 보이는 값(password=…, token=…, session=… 같은 꼴, 긴 무작위 문자열)은 가려서 출력합니다.
// decide.mjs 는 이 파일을 불러오지 않습니다(심판은 decide.mjs 한 파일만 불러옵니다).
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SECRET_LIKE = /\b(password|passwd|pwd|pass|secret|token|api[_-]?key|key|session|sid|authorization|bearer|cookie)\b\s*[=:]\s*[^\s&]+/giu;
const LONG_TOKEN = /\b[A-Za-z0-9_\-]{32,}\b/gu;

export function mask(text) {
  if (typeof text !== 'string') return '';
  return text.replace(SECRET_LIKE, (_, name) => `${name}=[가림]`).replace(LONG_TOKEN, '[가림]');
}

export function pick(alert) {
  return {
    time: typeof alert?.timestamp === 'string' ? alert.timestamp : '',
    srcip: typeof alert?.data?.srcip === 'string' ? mask(alert.data.srcip) : '',
    user: typeof alert?.data?.srcuser === 'string' ? mask(alert.data.srcuser) : '',
    level: Number.isInteger(alert?.rule?.level) ? alert.rule.level : null,
    description: mask(alert?.rule?.description ?? ''),
  };
}

export function readAlerts(fixture) {
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || !Array.isArray(fixture.alerts)) throw new Error('경보 묶음 형식이 아닙니다.');
  return fixture.alerts.map(pick);
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const fixture = JSON.parse(await readFile(join(root, 'xdr', 'fixtures', 'known-cve.json'), 'utf8'));
  const rows = readAlerts(fixture);
  for (const row of rows) console.log([row.time, row.srcip, row.user, row.level ?? '', row.description].join(' | '));
  console.log(`경보 ${fixture.alerts.length}건 · 뽑은 줄 ${rows.length}줄 · ${fixture.alerts.length === rows.length ? '같음' : '다름'}`);
  if (fixture.alerts.length !== rows.length) process.exitCode = 1;
}
