const CACHE_NAME = 'hidden-cloud-pwa-v2';
const APP_SHELL = [
  './',
  './index.html',
  './manifest.webmanifest',
  './hidden-cloud-logo.png',
  './pwa-icon-180.png',
  './pwa-icon-192.png',
  './pwa-icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  const isSameOrigin = url.origin === self.location.origin;
  const isStaticExternalAsset =
    request.destination === 'script' ||
    request.destination === 'style' ||
    request.destination === 'font' ||
    request.destination === 'image';

  if (isSameOrigin) {
    if (request.mode === 'navigate') {
      event.respondWith(
        fetch(request).catch(() => caches.match('./index.html'))
      );
      return;
    }

    event.respondWith(
      caches.match(request).then((cached) => {
        if (cached) return cached;
        return fetch(request).then((response) => {
          if (response.ok) {
            const copy = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
          }
          return response;
        });
      })
    );
    return;
  }

  // Cache libraries such as Firebase and SheetJS after the first online load.
  // API/data requests have no destination and intentionally remain network-only.
  if (isStaticExternalAsset) {
    event.respondWith(
      caches.match(request).then((cached) => {
        if (cached) return cached;
        return fetch(request).then((response) => {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
          return response;
        });
      })
    );
  }
});