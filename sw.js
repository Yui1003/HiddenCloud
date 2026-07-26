const CACHE_NAME = 'hidden-cloud-pwa-v3';
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
  const isApiRequest = isSameOrigin && url.pathname.startsWith('/api/');
  const isStaticExternalAsset =
    request.destination === 'script' ||
    request.destination === 'style' ||
    request.destination === 'font' ||
    request.destination === 'image';

  if (isSameOrigin && !isApiRequest) {
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

self.addEventListener('push', (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch (_) {
    payload = { title: 'Hidden Cloud Bleeding', body: event.data ? event.data.text() : '' };
  }

  const title = payload.title || 'Hidden Cloud Bleeding';
  const options = {
    body: payload.body || '',
    icon: payload.icon || './pwa-icon-192.png',
    badge: payload.badge || './pwa-icon-192.png',
    tag: payload.tag || 'hidden-cloud-bleeding',
    data: { url: './' },
    renotify: false,
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if ('focus' in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow(event.notification.data?.url || './');
    })
  );
});