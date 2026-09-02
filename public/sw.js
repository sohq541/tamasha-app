self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', () => {});

self.addEventListener('push', (event) => {
  let data = { title: 'YouSeries', body: 'You have a new notification' };
  try { data = event.data.json(); } catch (e) {}

  const url = data.filmId ? `/?film=${data.filmId}`
    : data.storyId ? `/?profile=${data.fromUserId}`
    : data.fromUserId ? `/?profile=${data.fromUserId}`
    : '/';

  event.waitUntil(
    self.registration.showNotification(data.title || 'YouSeries', {
      body: data.body || '',
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      data: { url }
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if ('focus' in client) { client.focus(); client.navigate(url); return; }
      }
      if (self.clients.openWindow) return self.clients.openWindow(url);
    })
  );
});
