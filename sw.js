const CACHE_NAME = 'securevault-v2.5.0';
const ASSETS = [
  './',
  './index.html',
  './splash.html',
  './style.css',
  './chatbot.css',
  './app.js',
  './crypto.js',
  './chatbot.js',
  './jszip.min.js',
  './qrious.min.js',
  './icon.svg',
  './manifest.json',
  './version.json',
  './js/auth-sync.js',
  './js/backup-engine.js',
  './js/version-updater.js',
  './js/copilot-ui.js'
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS).catch((err) => {
        console.warn('[ServiceWorker] Pre-cache warning:', err);
      });
    })
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            console.log('[ServiceWorker] Purging stale cache:', key);
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.action === 'SKIP_WAITING') {
    console.log('[ServiceWorker] Skip waiting command received.');
    self.skipWaiting();
  }
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  // Bypass cache for API endpoints, SSE streams, OAuth callbacks, and version.json checks
  if (
    url.pathname.startsWith('/api/') ||
    url.pathname.includes('/copilot') ||
    url.pathname.endsWith('version.json') ||
    e.request.method !== 'GET'
  ) {
    return e.respondWith(fetch(e.request));
  }

  // Network-first with cache fallback for static assets
  e.respondWith(
    fetch(e.request)
      .then((response) => {
        if (!response || response.status !== 200 || response.type !== 'basic') {
          return response;
        }
        const responseToCache = response.clone();
        caches.open(CACHE_NAME).then((cache) => {
          cache.put(e.request, responseToCache);
        });
        return response;
      })
      .catch(() => caches.match(e.request))
  );
});
