const CACHE = 'wifi-scanner-v1';
const ASSETS = ['/', '/index.html', '/css/style.css', '/js/app.js', '/js/api.js', '/js/ws.js'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  if (e.request.url.includes('/api/')) {
    e.respondWith(networkFirst(e.request));
  } else {
    e.respondWith(cacheFirst(e.request));
  }
});

async function networkFirst(req) {
  try {
    const net = await fetch(req);
    const c = await caches.open(CACHE);
    c.put(req, net.clone());
    return net;
  } catch { return caches.match(req) || new Response('Offline', { status: 503 }); }
}

async function cacheFirst(req) {
  const cached = await caches.match(req);
  return cached || fetch(req);
}
