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
    g100: { v: "$100", u: "折價", t: "配件滿千折百", from: "小遊戲過關" },
    exp100: { v: "$100", u: "折價", t: "配件滿千折百", from: "體驗區任務" },
    a9: { v: "9 折", u: "加購", t: "辦完 30 分鐘內加購配件", from: "防詐小測驗" }
  };
  function dealsFor(cat, walkIn) { var a = (DEAL_BY_CAT[cat] || DEAL_BY_CAT["異動/諮詢/維修"]).slice(); if (cat === "繳費/儲值") return a; if (walkIn) { a = ["exp"].concat(a.slice(0, 1)).concat(["add9"]); } return a.slice(0, 3); }
  window.QTLive = { cleanHost: cleanHost, parseLink: parseLink, linkOf: linkOf, pageUrl: pageUrl, sess: sess, crypto: cryptoApi, order: order, view: view, connect: connect, rand: rand, qrSvg: qrSvg, holdPatch: holdPatch, ruleGuess: ruleGuess, TS: TS, STATUS_ZH: STATUS_ZH, DEALS: DEALS, COUPONS: COUPONS, dealsFor: dealsFor };
})();
