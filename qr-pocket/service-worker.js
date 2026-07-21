const CACHE_NAME = 'qr-pocket-v3';
const APP_FILES = [
  './',
  './index.html',
  './notes.html',
  './scanner.html',
  './styles.css',
  './app.js',
  './notes.js',
  './scanner.js',
  './manifest.webmanifest',
  './icons/app-icon.svg',
  './vendor/scanner-engine.js'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_FILES))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(key => key.startsWith('qr-pocket-') && key !== CACHE_NAME).map(key => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;

  event.respondWith(
    caches.match(event.request).then(cached => {
      const fromNetwork = fetch(event.request).then(response => {
        if (response.ok || response.type === 'opaque') {
          const copy = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, copy));
        }
        return response;
      });

      return cached || fromNetwork.catch(() => {
        if (event.request.mode === 'navigate') return caches.match('./index.html');
        return Promise.reject(new Error('Resource unavailable offline'));
      });
    })
  );
});
