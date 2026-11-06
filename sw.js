// 叫號說：先抓最新版，沒網路時用上次的內容；影片不經過這裡（避免影響播放）
const CACHE = "qtalk-v1";
self.addEventListener("install", e => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));
self.addEventListener("fetch", e => {
  const r = e.request, u = new URL(r.url);
  if (r.method !== "GET" || u.origin !== location.origin || /\.mp4$/i.test(u.pathname) || r.headers.has("range")) return;
  e.respondWith(fetch(r).then(res => {
    if (res.ok) { const c = res.clone(); caches.open(CACHE).then(k => k.put(r, c)); }
    return res;
  }).catch(() => caches.match(r)));
});
