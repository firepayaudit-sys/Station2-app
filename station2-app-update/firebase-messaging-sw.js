/* ============ Pass It On — Background Push Notifications ============ */
// This runs in the background (even when the app isn't open) so a phone can
// receive a push notification when someone posts a new "Pass It On" note.

importScripts('https://www.gstatic.com/firebasejs/10.14.1/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.14.1/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey: "AIzaSyC1VU512CZ7j_7Tvw7zbp6ccaGhfNZcrK0",
  authDomain: "station-2-app.firebaseapp.com",
  databaseURL: "https://station-2-app-default-rtdb.firebaseio.com",
  projectId: "station-2-app",
  storageBucket: "station-2-app.firebasestorage.app",
  messagingSenderId: "55531570769",
  appId: "1:55531570769:web:13a7d9fb464e15963c5a70"
});

const messaging = firebase.messaging();

messaging.onBackgroundMessage((payload) => {
  const title = (payload.notification && payload.notification.title) || 'Pass It On';
  const body = (payload.notification && payload.notification.body) || 'New note posted.';
  self.registration.showNotification(title, {
    body: body,
    data: payload.data || {}
  });
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windowClients) => {
      for (const client of windowClients) {
        if ('focus' in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow('/#pass-it-on');
    })
  );
});
