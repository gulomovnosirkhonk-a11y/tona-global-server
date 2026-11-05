/* No messages, media, authenticated responses or tokens are cached. */
self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin ||
      event.request.mode !== 'navigate' || !['/', '/install'].includes(url.pathname)) return;
  event.respondWith(fetch(event.request).catch(() => new Response(
    '<!doctype html><html lang="uz"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TONA — Offline</title><h1>TONA</h1><p>Internetga ulaning va qayta urinib ko‘ring.</p><p>Xabarlar oflayn yuborilmaydi.</p><a href="/">Qayta ochish</a></html>',
    {status:503, headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Content-Security-Policy':"default-src 'none'; base-uri 'none'; frame-ancestors 'none'"}}
  )));
});
