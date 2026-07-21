const CACHE_NAME = "goblinpass-gen5-v6";
const APP_FILES = [
  "./", "./index.html", "./base.css", "./layout.css", "./style.css", "./dist/app.js", "./manifest.webmanifest",
  "./icons/icon-192.png", "./icons/icon-512.png"
];

self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(APP_FILES)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(key => key.startsWith("goblinpass-gen5-") && key !== CACHE_NAME).map(key => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", event => {
  if (event.request.method !== "GET") return;
  if (event.request.mode === "navigate") {
    event.respondWith(fetch(event.request).then(response => {
      if (response.ok) caches.open(CACHE_NAME).then(cache => cache.put(event.request, response.clone()));
      return response;
    }).catch(async () => await caches.match(event.request, { ignoreSearch: true }) || await caches.match("./index.html")));
    return;
  }
  event.respondWith(fetch(event.request).then(response => {
    if (response.ok && new URL(event.request.url).origin === self.location.origin) {
      caches.open(CACHE_NAME).then(cache => cache.put(event.request, response.clone()));
    }
    return response;
  }).catch(() => caches.match(event.request, { ignoreSearch: true })));
});
