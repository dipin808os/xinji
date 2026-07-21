// 用 CDP 驱动 headless Chrome：设 cookie → 打开心迹 → 点砚辞 → 截图
// 用法：node scripts/cdp-shot.mjs <token> <outPng> [theme] [afterMs]
import fs from 'fs';

const [, , TOKEN, OUT, THEME = 'day', AFTER = '2600'] = process.argv;
const PORT = 9222;

async function rpc(ws, id, method, params) {
  return new Promise((resolve) => {
    const onMsg = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.id === id) { ws.removeEventListener('message', onMsg); resolve(m.result); }
    };
    ws.addEventListener('message', onMsg);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

const list = await (await fetch(`http://localhost:${PORT}/json`)).json();
let page = list.find((t) => t.type === 'page');
if (!page) {
  page = await (await fetch(`http://localhost:${PORT}/json/new`)).json();
}
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));

let id = 1;
await rpc(ws, id++, 'Page.enable');
await rpc(ws, id++, 'Network.enable');
await rpc(ws, id++, 'Emulation.setDeviceMetricsOverride', {
  width: 900, height: 900, deviceScaleFactor: 2, mobile: false,
});
await rpc(ws, id++, 'Network.setCookie', {
  name: 'xinji_session', value: TOKEN, domain: 'localhost', path: '/', httpOnly: true,
});
// 强制主题
await rpc(ws, id++, 'Page.navigate', { url: `http://localhost:5178/?forcetheme=${THEME}` });
await new Promise((r) => setTimeout(r, 1500));
// 点开砚辞
await rpc(ws, id++, 'Runtime.evaluate', {
  expression: `document.getElementById('tabCompanion').click()`,
});
await new Promise((r) => setTimeout(r, Number(AFTER)));

const { data } = await rpc(ws, id++, 'Page.captureScreenshot', { format: 'png' });
fs.writeFileSync(OUT, Buffer.from(data, 'base64'));
console.log('saved', OUT);
ws.close();
process.exit(0);
