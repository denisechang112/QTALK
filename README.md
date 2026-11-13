# 叫號說 QTalk

台灣大哥大門市取號 App 提案原型（黑客節）。手機網頁版，打開 `index.html` 即可使用。

## 功能
- 線上取號、即時叫號看板、預約時段、全台門市選擇
- 取號前先寫下要辦的事，櫃台看板同步顯示（顧客內容只有櫃台看得到）
- 語音叫號，支援中文、English、日本語、한국어、Tiếng Việt、Bahasa Indonesia
- 小教室：防詐測驗、門市課程
- 等候時的小遊戲：小小店長、防詐偵探（`games/`）
- 櫃台看板與關帳總結（在「門市，先聽我說！！」區塊連點 3 下開啟）

## 手機版
- 會自動判斷：用手機或平板打開時是全螢幕的 App 畫面，畫面固定不會跟著滑動；用電腦打開時顯示模擬手機外框。
- 在手機上可以「加到主畫面」，之後從主畫面圖示打開，就像一般 App 一樣全螢幕、沒有瀏覽器網址列。
  - iPhone：用 Safari 打開 → 下方「分享」→「加入主畫面」
  - Android：用 Chrome 打開 → 右上角「⋮」→「安裝應用程式」或「加到主畫面」

## 現場同步 Demo（多裝置）
評審用手機掃 QR Code 取號，門市大螢幕與櫃台即時同步；櫃台叫號時，顧客手機會跳出畫面並播語音。
- `counter.html`：櫃台叫號台（建立場次、叫下一號、看顧客留言）
- `screen.html`：門市大螢幕（現在叫號、等候人數、取號 QR Code）
- 後端使用 Firebase Realtime Database 免費方案；不儲存電話號碼，顧客留言在手機端加密。
- 設定與當天流程請看 `現場Demo操作步驟.md`。不帶 QR Code 連結開啟 `index.html` 時，仍是原本的單機模擬版。

## 檔案
| 路徑 | 說明 |
|---|---|
| `index.html` | App 本體 |
| `games/` | 小遊戲 |
| `audio/<語言>/` | 預錄叫號語音（電腦上播放；手機有該語言語音時用手機內建語音） |
| `counter.html`、`screen.html`、`live.js` | 現場同步 Demo 的櫃台、大螢幕與同步核心 |
| `firebase-rules.json` | Firebase 安全規則 |
| `media/` | App 內的教學、宣傳與防詐影片及封面圖 |

## 注意
- 門市名單、等候時間、後台數據皆為示意。
- 預錄語音以開源離線語音模型產生（Kokoro、Piper、Mimic3，透過 sherpa-onnx）。
- QR Code 產生使用 Kazuhiko Arase 的 qrcode-generator（MIT 授權）。
