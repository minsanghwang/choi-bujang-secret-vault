// 설치형 웹앱의 서비스 워커입니다. 하는 일은 하나뿐입니다: 인터넷이 끊겼을 때 "오프라인 안내" 페이지를 보여 줍니다.
// - 자료(메모·공지)·로그인·승인 상태 같은 /api 응답과 /aleph.json은 가로채지도, 보관하지도 않습니다(항상 네트워크로만 갑니다).
// - 이 워커는 토큰·기기 키·승인 상태를 저장하지 않으며, 보관하는 것은 아래 정적 파일 몇 개뿐입니다.
// - 자료실을 여는 조건은 서버가 확인한 승인 결과뿐입니다. 설치 여부와 이 워커의 동작 여부는 판단에 쓰지 않습니다.
const CACHE = 'byteback-offline-v11';
const STATIC_FILES = ['/offline.html', '/manifest.webmanifest', '/icon-192.png', '/icon-512.png'];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(STATIC_FILES)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', event => {
  event.waitUntil(caches.keys()
    .then(names => Promise.all(names.filter(name => name !== CACHE).map(name => caches.delete(name))))
    .then(() => self.clients.claim()));
});

self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/') || url.pathname === '/aleph.json') return;   // 보호 자료·로그인·승인 상태는 보관하지 않습니다.
  if (request.mode === 'navigate') {
    // 화면 이동은 항상 네트워크를 먼저 쓰고, 연결이 없을 때만 오프라인 안내를 보여 줍니다(자료 화면을 보관하지 않음).
    event.respondWith(fetch(request).catch(() => caches.match('/offline.html')));
  }
});
