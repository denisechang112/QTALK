/* 叫號說・現場同步核心（顧客手機、櫃台叫號台、門市大螢幕共用）
   後端：Firebase Realtime Database 的 REST API＋即時串流（EventSource），不需要載入 Firebase SDK。
   資料只放在 /rooms/<場次代碼>/ 底下；場次代碼是亂數，只有拿到 QR Code／連結的人才進得去。
   顧客寫給櫃台的話在手機上就先加密，只有櫃台裝置解得開。不存電話號碼。 */
(function () {
  "use strict";
  var LOCAL = /^(localhost|127\.0\.0\.1)$/.test(location.hostname);

  /* ---------- 小工具 ---------- */
  function b64u(buf) { var b = new Uint8Array(buf), s = ""; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
  function unb64u(s) { s = String(s).replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; var bin = atob(s), u = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
  function rand(n) { var A = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789", u = new Uint8Array(n), s = ""; crypto.getRandomValues(u); for (var i = 0; i < n; i++) s += A[u[i] % A.length]; return s; }

  /* 把使用者貼上的「資料庫網址」整理成主機名稱；不是 Firebase 的網址一律不接受 */
  function cleanHost(input) {
    var s = String(input || "").trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "").toLowerCase();
    if (/^[a-z0-9-]+(\.[a-z0-9-]+)*\.(firebaseio\.com|firebasedatabase\.app)$/.test(s)) return s;
    if (LOCAL && /^(localhost|127\.0\.0\.1):\d+$/.test(s)) return s;
    return null;
  }
  /* 連結格式：#l=<資料庫主機>~<場次代碼>（櫃台加入連結多一個 &k=<金鑰>） */
  function parseLink(str) {
    var s = String(str == null ? location.hash + "&" + location.search : str);
    var m = s.match(/[#&?]l=([^&#]+)/); if (!m) return null;
    var v; try { v = decodeURIComponent(m[1]); } catch (e) { return null; }
    var p = v.split("~"), host = cleanHost(p[0]), room = p[1] || "";
    if (!host || !/^[A-Za-z0-9]{16,40}$/.test(room)) return null;
    var k = s.match(/[#&?]k=([A-Za-z0-9_-]{20,80})/);
    return { host: host, room: room, d: k ? k[1] : null };
  }
  function linkOf(sess, withKey) { return "l=" + sess.host + "~" + sess.room + (withKey && sess.d ? "&k=" + sess.d : ""); }
  function pageUrl(file, sess, withKey) { return new URL(file || "./", location.href).href.replace(/[#?].*$/, "") + "#" + linkOf(sess, withKey); }

  var SESS_KEY = "qt-live-sess";
  var sess = {
    load: function () { try { var o = JSON.parse(localStorage.getItem(SESS_KEY) || "null"); return o && cleanHost(o.host) && o.room ? o : null; } catch (e) { return null; } },
    save: function (o) { try { localStorage.setItem(SESS_KEY, JSON.stringify(o)); } catch (e) { } },
    clear: function () { try { localStorage.removeItem(SESS_KEY); } catch (e) { } }
  };

  /* ---------- 留言加密（ECDH P-256 + AES-GCM） ---------- */
  var subtle = window.crypto && crypto.subtle;
  function pubJwk(pub) { var p = pub.split("."); return { kty: "EC", crv: "P-256", x: p[0], y: p[1], ext: true }; }
  async function aesFrom(priv, pub) {
    var bits = await subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256);
    var h = await subtle.digest("SHA-256", bits);
    return subtle.importKey("raw", h, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }
  var cryptoApi = {
    ok: !!subtle,
    /* 櫃台建立場次時產生一組金鑰：pub 公開放在場次資料裡，d 只留在櫃台裝置 */
    genStaffKey: async function () {
      var kp = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
      var j = await subtle.exportKey("jwk", kp.privateKey);
      return { pub: j.x + "." + j.y, d: j.d };
    },
    /* 顧客手機：用場次公鑰把留言鎖起來 */
    seal: async function (pub, text) {
      if (!subtle || !pub || !text) return null;
      var staff = await subtle.importKey("jwk", pubJwk(pub), { name: "ECDH", namedCurve: "P-256" }, false, []);
      var eph = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
      var ej = await subtle.exportKey("jwk", eph.publicKey);
      var key = await aesFrom(eph.privateKey, staff), iv = crypto.getRandomValues(new Uint8Array(12));
      var ct = await subtle.encrypt({ name: "AES-GCM", iv: iv }, key, new TextEncoder().encode(text));
      return { e: ej.x + "." + ej.y, i: b64u(iv), c: b64u(ct) };
    },
    /* 櫃台裝置：用自己的金鑰解開 */
    open: async function (pub, d, sealed) {
      if (!subtle || !pub || !d || !sealed || !sealed.c) return null;
      try {
        var j = pubJwk(pub); j.d = d;
        var priv = await subtle.importKey("jwk", j, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
        var eph = await subtle.importKey("jwk", pubJwk(sealed.e), { name: "ECDH", namedCurve: "P-256" }, false, []);
        var key = await aesFrom(priv, eph);
        var pt = await subtle.decrypt({ name: "AES-GCM", iv: unb64u(sealed.i) }, key, unb64u(sealed.c));
        return new TextDecoder().decode(pt);
      } catch (e) { return null; }
    }
  };

  /* ---------- 號碼與排序：全部裝置用同一套算法，不需要中央發號 ---------- */
  /* 票的編號由建立順序決定：第 1 張 A101、第 2 張 A102…（Firebase 的自動鍵值本身就照時間排序） */
  function order(tickets) {
    var ids = Object.keys(tickets || {}).filter(function (id) { var t = tickets[id]; return t && typeof t === "object" && typeof t.st === "string"; }).sort();
    var a = 0, r = 0;   // 一般號 A101 起；開賣日預約取機 R001 起，兩種各自編號，互不影響
    return ids.map(function (id) { var t = tickets[id], no = t.k === "r" ? "R" + String(++r).padStart(3, "0") : "A" + (101 + a++), o = { id: id, no: no }; for (var k in t) o[k] = t[k]; ["pk", "cp"].forEach(function (k) { var v = o[k]; if (v && !Array.isArray(v)) o[k] = typeof v === "object" ? Object.keys(v).sort().map(function (x) { return v[x]; }) : []; }); return o; });
  }
  /* st：w 等候、c 已叫號、d 完成、s 過號、x 取消、b 已預約取機（還沒到店報到） */
  function view(room) {
    var all = order(room && room.tickets), waiting = all.filter(function (t) { return t.st === "w"; });
    var key = function (t) { return typeof t.sk === "number" ? t.sk : (typeof t.t === "number" ? t.t : 0); };   // sk：顧客按「晚一點」後的新位置
    waiting.sort(function (x, y) { return key(x) - key(y) || (x.id < y.id ? -1 : 1); });
    waiting = waiting.filter(function (t) { return t.p; }).concat(waiting.filter(function (t) { return !t.p; }));   // 優先號排前面
    var called = all.filter(function (t) { return t.st === "c"; }).sort(function (a, b) { return (a.ct || 0) - (b.ct || 0); });
    var desks = {}; called.forEach(function (t) { desks[t.desk || 1] = t; });   // 每個櫃台只留最新叫的那一位
    var last = called.length ? called[called.length - 1] : null;
    return { all: all, waiting: waiting, desks: desks, last: last, done: all.filter(function (t) { return t.st === "d"; }).length, meta: (room && room.meta) || null };
  }

  /* ---------- 連線 ---------- */
  function connect(host, room, onData, onStatus) {
    var base = (/^(localhost|127\.0\.0\.1):/.test(host) ? "http://" : "https://") + host + "/rooms/" + room;
    var data = null, es = null, mode = "sse", lastEvt = 0, gotFirst = false, closed = false, status = "connecting", fails = 0, pollT = null, watchT = null, sseRetryAt = 0;
    function setStatus(s, detail) { if (s !== status) { status = s; try { onStatus && onStatus(s, detail); } catch (e) { } } }
    function emit() { try { onData(data || {}); } catch (e) { console.error(e); } }
    function apply(path, val, merge) {
      var parts = String(path || "/").split("/").filter(Boolean);
      if (merge && val && typeof val === "object") { Object.keys(val).forEach(function (k) { apply(parts.concat(k.split("/")).join("/"), val[k], false); }); return; }
      if (!parts.length) { data = val; return; }
      if (data == null || typeof data !== "object") data = {};
      var o = data;
      for (var i = 0; i < parts.length - 1; i++) { if (o[parts[i]] == null || typeof o[parts[i]] !== "object") { if (val == null) return; o[parts[i]] = {}; } o = o[parts[i]]; }
      if (val == null) delete o[parts[parts.length - 1]]; else o[parts[parts.length - 1]] = val;
    }
    async function req(method, path, body) {
      var r = await fetch(base + (path || "") + ".json", { method: method, body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store" });
      if (!r.ok) { var e = new Error("HTTP " + r.status); e.status = r.status; try { e.detail = (await r.json()).error; } catch (_) { } throw e; }
      return r.json();
    }
    async function refetch() {
      try { data = await req("GET", ""); gotFirst = true; fails = 0; setStatus("live"); emit(); return true; }
      catch (e) { fails++; setStatus(e.status === 401 || e.status === 403 ? "denied" : e.status === 404 ? "notfound" : "offline", e.detail); return false; }
    }
    function startPoll() {
      if (closed) return; mode = "poll"; try { es && es.close(); } catch (e) { } es = null;
      clearTimeout(pollT);
      (function loop() { if (closed || mode !== "poll") return; refetch().then(function (ok) {
        if (closed || mode !== "poll") return;
        if (ok && window.EventSource && Date.now() > sseRetryAt) { sseRetryAt = Date.now() + 30000; openSSE(true); }   // 定期試著換回即時串流
        pollT = setTimeout(loop, ok ? 1500 : 3000); }); })();
    }
    function openSSE(trial) {
      if (closed) return;
      if (!window.EventSource) { startPoll(); return; }
      var mine; try { mine = new EventSource(base + ".json"); } catch (e) { startPoll(); return; }
      var opened = false, errs = 0;
      function first() { if (opened) return; opened = true; if (es && es !== mine) { try { es.close(); } catch (e) { } } es = mine; mode = "sse"; clearTimeout(pollT); }
      function on(ev, merge) { mine.addEventListener(ev, function (e) {
        if (closed) { mine.close(); return; }
        var m; try { m = JSON.parse(e.data); } catch (_) { return; }
        first(); if (es !== mine) { mine.close(); return; }
        lastEvt = Date.now(); fails = 0; apply(m.path, m.data, merge); gotFirst = true; setStatus("live"); emit(); }); }
      on("put", false); on("patch", true);
      mine.addEventListener("keep-alive", function () { lastEvt = Date.now(); });
      mine.addEventListener("cancel", function () { mine.close(); if (es === mine) { es = null; startPoll(); } });
      mine.addEventListener("auth_revoked", function () { mine.close(); if (es === mine) { es = null; startPoll(); } });
      mine.onerror = function () {
        errs++;
        if (!opened) { if (mine.readyState === 2 || errs >= 2) { mine.close(); if (!trial && mode !== "poll") startPoll(); } return; }   // 串流開不起來：改用輪詢
        if (es !== mine) return;
        setStatus("reconnecting");
        if (mine.readyState === 2 || errs >= 4) { mine.close(); es = null; startPoll(); }
      };
      if (!trial) { es = mine; setTimeout(function () { if (!opened && !closed && es === mine) { mine.close(); es = null; startPoll(); } }, 7000); }
    }
    function resync() { if (closed) return; if (mode === "poll") refetch(); else { lastEvt = Date.now(); openSSE(false); } }
    function onVis() { if (!document.hidden) resync(); }
    document.addEventListener("visibilitychange", onVis); window.addEventListener("online", resync); window.addEventListener("pageshow", onVis);
    watchT = setInterval(function () { if (!closed && mode === "sse" && gotFirst && Date.now() - lastEvt > 50000) resync(); }, 5000);
    openSSE(false);

    function localSv(v) { if (v && typeof v === "object") { if (v[".sv"] === "timestamp") return Date.now(); var o = Array.isArray(v) ? [] : {}; for (var k in v) o[k] = localSv(v[k]); return o; } return v; }
    async function after(fn) { if (mode === "poll" || !gotFirst) await refetch(); else if (fn) { fn(); emit(); } }
    return {
      get data() { return data || {}; }, get status() { return status; }, get mode() { return mode; },
      post: async function (path, val) { var r = await req("POST", path, val); await after(function () { var p = path.split("/").filter(Boolean), o = data || {}; for (var i = 0; i < p.length; i++) o = (o && o[p[i]]) || {}; if (!o[r.name]) apply(path + "/" + r.name, localSv(val), false); }); return r.name; },
      patch: async function (path, val) { await req("PATCH", path, val); await after(null); },
      put: async function (path, val) { await req("PUT", path, val); await after(null); },
      del: async function (path) { await req("DELETE", path); await after(null); },
      resync: resync,
      close: function () { closed = true; clearTimeout(pollT); clearInterval(watchT); try { es && es.close(); } catch (e) { } document.removeEventListener("visibilitychange", onVis); window.removeEventListener("online", resync); window.removeEventListener("pageshow", onVis); }
    };
  }


  /* QR Code（需要先載入 qrcode.js）：輸出 SVG，放多大都清楚 */
  function qrSvg(text) {
    if (typeof qrcode !== "function") return "";
    var q = qrcode(0, "M"); q.addData(text); q.make();
    var n = q.getModuleCount(), d = "";
    for (var r = 0; r < n; r++) for (var c = 0; c < n; c++) if (q.isDark(r, c)) d += "M" + c + "," + r + "h1v1h-1z";
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="-3 -3 ' + (n + 6) + " " + (n + 6) + '" shape-rendering="crispEdges" role="img" aria-label="QR Code"><rect x="-3" y="-3" width="' + (n + 6) + '" height="' + (n + 6) + '" fill="#fff"/><path d="' + d + '" fill="#15142a"/></svg>';
  }
  /* 「我需要晚一點」：把自己排到目前位置後面 n 位（只能用一次）。回傳要寫回資料庫的欄位 */
  function holdPatch(v, id, n) {
    var w = v.waiting.filter(function (t) { return t.id !== id; });
    var me = v.all.filter(function (t) { return t.id === id; })[0]; if (!me) return null;
    var idx = v.waiting.map(function (t) { return t.id; }).indexOf(id); if (idx < 0) idx = 0;   // 已被叫號的，從最前面往後算
    var key = function (t) { return typeof t.sk === "number" ? t.sk : (typeof t.t === "number" ? t.t : 0); };
    var pool = w.filter(function (t) { return !!t.p === !!me.p; });
    var pos = Math.min(pool.length, idx + n), prev = pool[pos - 1], next = pool[pos];
    var sk = prev ? (next ? (key(prev) + key(next)) / 2 : key(prev) + 1000) : (next ? key(next) - 1000 : Date.now());
    return { st: "w", sk: sk, held: true, desk: null, ct: null };
  }
  /* 留言用的簡單規則判斷（沒有 AI 時使用） */
  var RULES = [["繳費/儲值", /繳費|儲值|繳帳單|帳單|欠費|帳款/], ["網路取貨/預約取件", /取貨|取件|網路訂|訂單|預購|預約取/], ["異動/諮詢/維修", /壞|破|維修|故障|摔|改|異動|諮詢|問|斷線|收訊|訊號|設定|詐騙|eSIM|esim|轉卡|漫遊|出國/], ["續約/換約/新申辦", /續約|換約|到期|合約|新辦|申辦|方案|門號|攜碼|家庭|換手機|新機/]];
  function ruleGuess(text) { for (var i = 0; i < RULES.length; i++) if (RULES[i][1].test(text || "")) return RULES[i][0]; return null; }
  var TS = { ".sv": "timestamp" };
  var STATUS_ZH = { connecting: "連線中…", live: "已連線", reconnecting: "重新連線中…", offline: "連不上網路", denied: "資料庫拒絕存取（請檢查安全規則）", notfound: "找不到資料庫（請檢查網址）" };
  /* ---------- 門市優惠（示意內容，正式活動請與行銷、門市營運確認）：優惠與預選都綁在號碼上，不綁帳號 ---------- */
  var DEALS = {
    trade: { sv: 1000, at: "櫃台估價", ic: "♻️", t: "舊機回收加碼折抵", s: "最高再折 $1,000・請帶舊手機", prep: "舊機回收估價" },
    glass: { sv: 690, at: "櫃台代貼", ic: "🛡️", t: "續約送玻璃保護貼", s: "現場免費代貼", prep: "玻璃保護貼（代貼）" },
    acc100: { sv: 100, at: "配件牆", ic: "🔌", t: "配件滿千折百", s: "保護殼、快充頭都適用", prep: "配件（保護殼、快充頭）" },
    port: { sv: 300, at: "櫃台", ic: "📶", t: "攜碼送 mo 幣", s: "攜碼新申辦加贈", prep: "攜碼文件" },
    family: { sv: 200, at: "櫃台試算", per: "每月", ic: "👨‍👩‍👧", t: "家人一起辦享家庭方案", s: "第二門起月租優惠", prep: "家庭方案試算" },
    case: { sv: 300, at: "配件牆", ic: "📱", t: "保護殼＋快充頭組合價", s: "比單買省 $300", prep: "保護殼＋快充頭" },
    loaner: { sv: 0, at: "櫃台", free: "免費", ic: "🔧", t: "維修期間免費借備用機", s: "送修當天可借", prep: "備用機" },
    esim: { sv: 300, at: "櫃台", ic: "📲", t: "取機當天轉 eSIM 免手續費", s: "櫃台協助轉移", prep: "eSIM 轉移" },
    autopay: { sv: 100, at: "櫃台", ic: "💳", t: "設定自動扣繳送 mo 幣", s: "繳費順便設定", prep: "" },
    exp: { sv: 100, at: "體驗區", ic: "👀", t: "去體驗區試 iPhone Duo", s: "掃體驗區 QR 送 $100 配件券", walk: true },
    add9: { sv: 0, at: "結帳櫃台", free: "9 折", ic: "🛍️", t: "辦完 30 分鐘內加購 9 折", s: "保護殼、玻璃貼、快充頭", prep: "加購配件" }
  };
  var DEAL_BY_CAT = { "續約/換約/新申辦": ["trade", "glass", "acc100"], "網路取貨/預約取件": ["esim", "case", "glass"], "異動/諮詢/維修": ["loaner", "case", "family"], "繳費/儲值": ["autopay"] };
  var COUPONS = {
    c100: { v: "$100", u: "折價", t: "配件滿千折百", from: "到店小禮" },
    g100: { v: "$100", u: "折價", t: "配件滿千折百", from: "防詐任務" },
    exp100: { v: "$100", u: "折價", t: "配件滿千折百", from: "體驗區任務" },
    a9: { v: "9 折", u: "加購", t: "辦完 30 分鐘內加購配件", from: "防詐小測驗" }
  };

  /* 優惠圖示：和 LINE「門市取號」6 格同一套線稿（深藍線＋橘色重點） */
  var ICON = {
    trade: '<rect x="3.5" y="3.5" width="9" height="16" rx="2"/><path d="M7 16.5h2"/><path class="ac" d="M15.5 8.5a5 5 0 0 1 5 5"/><path class="ac" d="M20.5 10.5v3h-3"/><path class="ac" d="M20.5 17.5a5 5 0 0 1-5 2.5"/><path class="ac" d="M15.5 17.5v2.5h3"/>',
    glass: '<rect x="6" y="2.5" width="12" height="19" rx="2.5"/><path d="M10.5 18.5h3"/><path class="ac" d="M9 9.5l4-4M9 14l6-6"/>',
    acc100: '<path d="M3.5 12.2V4.5a1 1 0 0 1 1-1h7.7l8.3 8.3a1.5 1.5 0 0 1 0 2.1l-6.6 6.6a1.5 1.5 0 0 1-2.1 0z"/><circle cx="8" cy="8" r="1.4"/><path class="ac" d="M10.8 15.7l4.9-4.9"/><path class="ac" d="M11.2 11.3h.01M15.3 15.4h.01" stroke-width="2.8"/>',
    port: '<path d="M4 8h14l-3.5-3.5"/><path d="M20 16H6l3.5 3.5"/><circle class="ac" cx="12" cy="12" r="1.7"/>',
    family: '<circle cx="8.5" cy="7.5" r="3"/><path d="M3 20a5.5 5.5 0 0 1 11 0"/><circle class="ac" cx="17" cy="9.5" r="2.4"/><path class="ac" d="M15.5 14.3A4.5 4.5 0 0 1 21.5 18.5V20h-5"/>',
    case: '<path d="M8.5 3v4M15.5 3v4"/><path d="M5.5 7h13v3.5a6.5 6.5 0 0 1-13 0z"/><path d="M12 17v4"/><path class="ac" d="M12.9 9l-2.2 2.8h2.6l-2.2 2.8"/>',
    loaner: '<rect x="3.5" y="3" width="9" height="17" rx="2"/><path d="M7 17h2"/><path class="ac" d="M18.2 7.2a3 3 0 0 0-2.8 4.1L13 13.7l1.9 1.9 2.4-2.4a3 3 0 0 0 4.1-2.8l-1.8 1.7-1.7-.4-.4-1.7z"/>',
    esim: '<rect x="6" y="6" width="12" height="12" rx="2.2"/><path d="M9.5 3v3M14.5 3v3M9.5 18v3M14.5 18v3M3 9.5h3M3 14.5h3M18 9.5h3M18 14.5h3"/><rect class="ac" x="9.5" y="9.5" width="5" height="5" rx="1"/>',
    autopay: '<rect x="3" y="5.5" width="18" height="13" rx="2.5"/><path d="M3 9.5h18"/><path class="ac" d="M8.5 14.5l2 2 4-4"/>',
    exp: '<rect x="7" y="2.5" width="10" height="19" rx="2.2"/><path d="M10.5 18.5h3"/><path class="ac" d="M12 7.5l.9 1.9 1.9.9-1.9.9-.9 1.9-.9-1.9-1.9-.9 1.9-.9z"/><path class="ac" d="M3.5 6l1.6 1M3 10.5h2M20.5 6l-1.6 1M21 10.5h-2"/>',
    add9: '<path d="M5 8h14l-1 12.5H6z"/><path d="M9 8V6.5a3 3 0 0 1 6 0V8"/><path class="ac" d="M10 16l4-4.5"/><path class="ac" d="M10.2 12h.01M13.8 16h.01" stroke-width="2.8"/>',
    gift: '<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M3 7.5h18v3H3zM12 7.5V20"/><path class="ac" d="M12 7.5c-1.2-3-5-3.6-5-1.2s5 1.2 5 1.2zm0 0c1.2-3 5-3.6 5-1.2s-5 1.2-5 1.2z"/>',
    game: '<path d="M7 7.5h10a4 4 0 0 1 4 4V15a2.5 2.5 0 0 1-4.4 1.6L15 14.5H9l-1.6 2.1A2.5 2.5 0 0 1 3 15v-3.5a4 4 0 0 1 4-4z"/><path d="M7.5 10v3.5M5.8 11.8h3.4"/><path class="ac" d="M15.5 10.8h.01M17.5 12.8h.01" stroke-width="2.8"/>',
    check: '<circle cx="12" cy="12" r="8.5"/><path class="ac" d="M8 12.5l2.7 2.7L16 10"/>',
    book: '<path d="M5 4.5A1.5 1.5 0 0 1 6.5 3H19v15H6.5A1.5 1.5 0 0 0 5 19.5z"/><path d="M5 19.5A1.5 1.5 0 0 0 6.5 21H19v-3"/><path class="ac" d="M9 7.5h6M9 11h4"/>',
    bag: '<path d="M5 8h14l-1 12.5H6z"/><path d="M9 8V6.5a3 3 0 0 1 6 0V8"/><path class="ac" d="M9 12a3 3 0 0 0 6 0"/>',
    coins: '<ellipse cx="9.5" cy="6.5" rx="6" ry="2.5"/><path d="M3.5 6.5v4c0 1.4 2.7 2.5 6 2.5s6-1.1 6-2.5v-4"/><path class="ac" d="M8.5 15v2.5c0 1.4 2.7 2.5 6 2.5s6-1.1 6-2.5v-4c0-1.2-1.9-2.2-4.5-2.4"/>',
    pin: '<path d="M12 21s-6.5-5.5-6.5-11a6.5 6.5 0 0 1 13 0c0 5.5-6.5 11-6.5 11z"/><circle class="ac" cx="12" cy="10" r="2.3"/>'
  };
  var CP_ICON = { c100: "gift", g100: "game", exp100: "exp", a9: "check" };
  /* icon(名稱, {c:線條色, a:重點色}) → 一段 SVG 字串 */
  function icon(k, o) { o = o || {}; var p = ICON[k] || ICON[CP_ICON[k]] || ICON.gift; return '<svg class="qi" viewBox="0 0 24 24" fill="none" stroke="' + (o.c || "#2D2E67") + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + p.replace(/class="ac"/g, 'stroke="' + (o.a || "#E8893A") + '"') + "</svg>"; }
  function dealsFor(cat, walkIn) { var a = (DEAL_BY_CAT[cat] || DEAL_BY_CAT["異動/諮詢/維修"]).slice(); if (cat === "繳費/儲值") return a; if (walkIn) { a = ["exp"].concat(a.slice(0, 1)).concat(["add9"]); } return a.slice(0, 3); }
  window.QTLive = { cleanHost: cleanHost, parseLink: parseLink, linkOf: linkOf, pageUrl: pageUrl, sess: sess, crypto: cryptoApi, order: order, view: view, connect: connect, rand: rand, qrSvg: qrSvg, holdPatch: holdPatch, ruleGuess: ruleGuess, TS: TS, STATUS_ZH: STATUS_ZH, DEALS: DEALS, COUPONS: COUPONS, dealsFor: dealsFor, icon: icon, CP_ICON: CP_ICON };
})();
