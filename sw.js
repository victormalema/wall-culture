const CACHE_NAME = 'echora-shell-v2';
const SHELL_FILES = [
  '/',
  '/home.html',
  '/manifest.json'
];
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES))
  );
  self.skipWaiting();
});
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});
// Network-first for API calls and HTML pages (so deploys always reach users),
// cache-first for everything else (images, css, js, etc.)
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.pathname.startsWith('/api/')) {
    return; // let API calls go straight to network, no caching
  }

  const isHTML =
    event.request.mode === 'navigate' ||
    url.pathname.endsWith('.html') ||
    url.pathname === '/';

  if (isHTML) {
    // Network-first: always try to fetch the latest page.
    // Fall back to cache only if the network request fails (e.g. offline).
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => caches.match(event.request))
    );
    return;
  }

  // Cache-first for static assets
  event.respondWith(
    caches.match(event.request).then((cached) => {
      return (
        cached ||
        fetch(event.request).then((response) => {
          if (event.request.method === 'GET' && response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return response;
        })
      );
    })
  );
});