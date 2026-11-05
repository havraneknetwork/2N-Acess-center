// Service Worker – 2N Door Unlocker PWA v2
// Strategie:
//   - Statické assety: Cache-first s automatickým refresh na pozadí (Stale-While-Revalidate)
//   - API requesty: Network-only (nikdy se necachují – obsahují dynamická data a autentizaci)
//   - Navigace offline: Zobrazí offline.html fallback

const CACHE_VERSION = 'v20';
const CACHE_NAME = `door-unlocker-${CACHE_VERSION}`;

// Shell aplikace – předem uložené assety při instalaci
const PRECACHE_ASSETS = [
  '/',
  '/login.html',
  '/offline.html',
  '/xtrastyle.css',
  '/oneui.css',
  '/app.js',
  '/login.js',
  '/manifest.json',
  '/icons/icon-72x72.png',
  '/icons/icon-96x96.png',
  '/icons/icon-128x128.png',
  '/icons/icon-144x144.png',
  '/icons/icon-152x152.png',
  '/icons/icon-192x192.png',
  '/icons/icon-384x384.png',
  '/icons/icon-512x512.png'
];

// ============================================================================
// INSTALL – Pre-cache app shell
// ============================================================================
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(PRECACHE_ASSETS))
      .then(() => self.skipWaiting())
  );
});

// ============================================================================
// ACTIVATE – Cleanup old caches and take control immediately
// ============================================================================
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys
          .filter(key => key.startsWith('door-unlocker-') && key !== CACHE_NAME)
          .map(key => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

// ============================================================================
// FETCH – Smart routing
// ============================================================================
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Skip non-GET and cross-origin requests
  if (event.request.method !== 'GET') return;
  if (url.origin !== self.location.origin) return;

  // API requests → Network-only, never cache (auth, CSRF, dynamic data)
  if (url.pathname.startsWith('/api/')) {
    return;
  }

  // Navigation requests (HTML pages) → Network-first with offline fallback
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          // Cache successful navigation responses for offline use
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => {
          // Offline → try cache, then offline fallback page
          return caches.match(event.request, { ignoreSearch: true })
            .then(cached => cached || caches.match('/offline.html'));
        })
    );
    return;
  }

  // Skripty a styly (.js, .css) → Network-first, aby se vždy načetla aktuální verze
  if (url.pathname.endsWith('.js') || url.pathname.endsWith('.css')) {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => caches.match(event.request))
    );
    return;
  }

  // Static assets (CSS, JS, images, fonts) → Stale-While-Revalidate
  event.respondWith(
    caches.match(event.request, { ignoreSearch: true }).then(cached => {
      const fetchPromise = fetch(event.request)
        .then(response => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => {
          // If network fails and we have no cache, return 503
          if (cached) return cached;
          return new Response('Offline', { status: 503, statusText: 'Service Unavailable' });
        });

      // Return cached version immediately (if available), update in background
      return cached || fetchPromise;
    })
  );
});

// ============================================================================
// MESSAGE – Handle skipWaiting from client
// ============================================================================
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// ============================================================================
// PUSH – Příjem oznámení ze serveru (např. někdo zvoní / neoprávněný pokus)
// ============================================================================
self.addEventListener('push', event => {
  let data = {
    title: 'Dveře Šešule',
    body: 'Někdo zvoní u dveří.',
    icon: '/icons/icon-192x192.png',
    badge: '/icons/icon-96x96.png'
  };

  if (event.data) {
    try {
      const parsed = event.data.json();
      data = Object.assign(data, parsed);
    } catch (e) {
      data.body = event.data.text() || data.body;
    }
  }

  const options = {
    body: data.body || 'Někdo zvoní u dveří.',
    icon: data.icon || '/icons/icon-192x192.png',
    badge: data.badge || '/icons/icon-96x96.png',
    vibrate: [250, 100, 250, 100, 250],
    tag: 'door-bell-notification',
    renotify: true,
    data: data.data || { url: '/' },
    actions: [
      { action: 'open', title: 'Otevřít aplikaci' }
    ]
  };

  event.waitUntil(
    self.registration.showNotification(data.title || 'Dveře Šešule', options)
  );
});

// ============================================================================
// NOTIFICATION CLICK – Otevření / zaostření aplikace po kliknutí na notifikaci
// ============================================================================
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const urlToOpen = (event.notification.data && event.notification.data.url) || '/';
  const targetUrl = new URL(urlToOpen, self.location.origin);
  if (targetUrl.origin !== self.location.origin) {
    targetUrl.href = `${self.location.origin}/`;
  }

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windowClients => {
      for (const client of windowClients) {
        if (client.url.startsWith(self.location.origin) && 'navigate' in client && 'focus' in client) {
          return client.navigate(targetUrl.href).then(() => client.focus());
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(targetUrl.href);
      }
    })
  );
});
