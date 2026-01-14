// Service Worker for Mana Mingle PWA
const CACHE_NAME = 'mana-mingle-v3';
const urlsToCache = [
  '/',
  '/index.html',
  '/chat.html',
  '/videochat.html',
  '/groupchat.html',
  '/contact.html',
  '/privacy-policy.html',
  '/terms-of-service.html',
  '/report.html',
  '/admin.html',
  '/cookie-policy.html',
  '/404.html',
  '/mana.png',
  '/js/ad-manager.js',
  'https://cdn.socket.io/4.7.2/socket.io.min.js',
  'https://cdn.jsdelivr.net/npm/nsfwjs@latest/dist/nsfwjs.min.js',
  'https://fonts.googleapis.com/css2?family=Baloo+Tamma+2:wght@400;500;600;700&family=Rajdhani:wght@500;600;700&display=swap',
  'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap'
];

// Install event
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('Opened cache');
        return cache.addAll(urlsToCache);
      })
      .catch((err) => {
        console.error('Cache addAll failed:', err);
      })
  );
});

// Fetch event - Network first for HTML, Stale-while-revalidate for assets
self.addEventListener('fetch', (event) => {
  const requestUrl = new URL(event.request.url);

  // Network first for HTML pages to ensure fresh content
  if (event.request.headers.get('accept').includes('text/html')) {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          const responseToCache = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache);
          });
          return response;
        })
        .catch(() => {
          return caches.match(event.request).then((response) => {
            return response || caches.match('/404.html');
          });
        })
    );
  } else {
    // Stale-while-revalidate for other assets (images, css, js)
    event.respondWith(
      caches.match(event.request).then((cachedResponse) => {
        const fetchPromise = fetch(event.request).then((networkResponse) => {
          caches.open(CACHE_NAME).then((cache) => {
             // Check if valid response before caching
             try {
               if (networkResponse && networkResponse.status === 200 && networkResponse.type === 'basic') {
                 const responseToCache = networkResponse.clone();
                 cache.put(event.request, responseToCache).catch(() => {});
               }
             } catch (e) {
               // ignore clone errors
             }
          });
          return networkResponse;
        });
        return cachedResponse || fetchPromise;
      })
    );
  }
});

// Activate event - Clean up old caches
self.addEventListener('activate', (event) => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});
