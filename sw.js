const CACHE_NAME = 'securevault-v1';
const ASSETS = [
  './',
  './index.html',
  './style.css',
  './app.js',
  './crypto.js',
  './jszip.min.js',
  './qrious.min.js',
  './icon.svg',
  './manifest.json'
];

self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  // Network-first strategy for development, falling back to cache
  e.respondWith(
    fetch(e.request).then(response => {
      // Only cache valid HTTP and GET requests
      if (!response || response.status !== 200 || response.type !== 'basic' || e.request.method !== 'GET' || !e.request.url.startsWith('http')) {
        return response;
      }
      return caches.open(CACHE_NAME).then(cache => {
        cache.put(e.request, response.clone());
        return response;
      });
    }).catch(() => caches.match(e.request))
  );
});
