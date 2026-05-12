// ═══════════════════════════════════════════════════════════════════
// ⚙️  可调参数
// ═══════════════════════════════════════════════════════════════════
//
// ┌─ CFG.chunk ───────────────────────────────────────────────────────
// │  TCP 上行读取缓冲区大小（字节）。每次从 TCP readable 读取的最大块。
// │  • 调大：减少读取次数，提升大文件/流媒体吞吐（内存占用相应增加）
// │  • 调小：降低每块延迟，对交互型流量更友好
// │  建议范围：32KB ~ 256KB
// │
// ├─ CFG.dnPack ──────────────────────────────────────────────────────
// │  下行发送聚合缓冲区大小（字节）。mkDn 内部积累到此大小时强制发出一帧。
// │  • 调大：减少 WS 帧数量，降低帧头开销，适合大流量场景
// │  • 调小：减少单帧等待，适合小包/低延迟场景
// │  建议范围：16KB ~ 128KB；需 < CFG.chunk
// │
// ├─ CFG.dnTail ──────────────────────────────────────────────────────
// │  下行尾部阈值（字节）。缓冲区剩余空间低于此值时立即发出，不等定时器。
// │  防止缓冲区接近满时仍等待新数据导致微小延迟。
// │  建议设为 CFG.dnPack 的 1.5% ~ 3%（默认 512 = 32KB × 1.6%）
// │
// ├─ CFG.dnMs ────────────────────────────────────────────────────────
// │  下行定时器兜底间隔（毫秒）。低流量时超过此时间强制刷出积累数据。
// │  实际最小值为 max(CFG.dnMs, 1)，设为 0 等价于 1ms。
// │  • 调大：进一步聚合小包，适合大文件批量传输
// │  • 调小（0~5）：降低小流量场景的额外延迟
// │  建议范围：0 ~ 16ms
// │
// ├─ CFG.upPack ──────────────────────────────────────────────────────
// │  上行队列单次 bundle 合并的最大字节数。多个上行数据块会被合并成
// │  不超过此大小的单次 TCP write，减少写入次数。
// │  建议范围：8KB ~ 64KB
// │
// ├─ CFG.upQMax ──────────────────────────────────────────────────────
// │  上行队列最大积压字节数（安全阀）。超过此值时关闭连接防止内存耗尽。
// │  正常使用远不会触及，仅作为极端情况保护。
// │  建议范围：64KB ~ 1MB
// │
// ├─ CFG.maxED ───────────────────────────────────────────────────────
// │  Early Data（sec-websocket-protocol 头）允许的最大解码前长度（字节）。
// │  超过此长度的 ED 头将被忽略（视为无 ED）。
// │  通常无需修改；如客户端 ED 数据较大可适当调大。
// │
// └─ CFG.concur ──────────────────────────────────────────────────────
//    TCP 并发竞速连接数。同时向同一目标发起 N 路连接，取最快握手成功的，
//    其余连接随后关闭（类似 Happy Eyeballs）。
//    • 1：禁用竞速，单连接，最省资源
//    • 2~4：平衡速度与资源，适合大多数场景
//    • 调大：对高丢包/高延迟线路改善首包延迟，但会消耗更多 TCP 配额
//    建议范围：1 ~ 4
//
// ────────────────────────────────────────────────────────────────────
// 【预设A：大流量优先】适合峰值突发、大文件、高吞吐优先场景
// const CFG = { id: '88888888-8888-8888-8888-888888888888', chunk: 128 * 1024, dnPack: 64 * 1024, dnTail: 1024, dnMs: 8, upPack: 32 * 1024, upQMax: 512 * 1024, maxED: 8 * 1024, concur: 4 };
//
// 【预设B：低延迟优先】适合交互型流量、高连接数、混合场景（当前启用）
const CFG = { id: '88888888-8888-8888-8888-888888888888', chunk: 64 * 1024, dnPack: 32 * 1024, dnTail: 512, dnMs: 0, upPack: 16 * 1024, upQMax: 256 * 1024, maxED: 8 * 1024, concur: 4 };

// ────────────────────────────────────────────────────────────────────
// 连接超时（毫秒）
const 默认备用小可爱地址 = 'dsl253-007-079.nyc1.dsl.speakeasy.net';  //兜底落地IP，默认为某美国住宅IP，建议修改成你自己的
//
// 主连接超时毫秒：直连目标地址时的 TCP 握手等待上限。
// 超时后自动降级到备用地址。国内节点：500~1500ms；跨国节点：1500~3000ms
const 主连接超时毫秒 = 2000;
//
// 备用连接超时毫秒：连接备用/兜底地址时的等待上限。
// 通常比主连接超时稍长，给备用节点更多时间。
const 备用连接超时毫秒 = 4000;

// ────────────────────────────────────────────────────────────────────
// TXT 地址缓存参数（一般无需修改）
//
// txt缓存生存期ms：成功获取地址后的本地缓存有效期（毫秒）。
// 60s 内同一 URL 的并发请求全部命中缓存，不重复 fetch。
const txt缓存生存期ms = 60 * 1000;
//
// txt失败缓存生存期ms：fetch 失败后写入兜底缓存的有效期（毫秒）。
// 防止目标不可达时高并发频繁重试，消耗 CF 子请求配额。
const txt失败缓存生存期ms = 10 * 1000;

// ═══════════════════════════════════════════════════════════════════

// =====================================================================
// 🔥 模块级预热：Worker 冷启动时立即触发一次 TXT 地址 fetch
// 让缓存在第一个真实请求到来前就热好，高并发时后续请求直接命中缓存 0 延迟
// 注意：CF Workers 模块顶层不能 await，用非阻塞触发即可
// =====================================================================
let _已预热 = false;
const _预热地址 = addr => { if (_已预热) return; _已预热 = true; 获取动态地址(addr).catch(() => {}); };

// =====================================================================
// 🏎️ 底层：16连平铺解构 (V8引擎提速)
// =====================================================================
const hex = c => (c > 64 ? c + 9 : c) & 0xF;
const idB = new Uint8Array(16), dec = new TextDecoder('utf-8');
for (let i = 0, p = 0, c, h; i < 16; i++) {
c = CFG.id.charCodeAt(p++); c === 45 && (c = CFG.id.charCodeAt(p++));
h = hex(c);
c = CFG.id.charCodeAt(p++); c === 45 && (c = CFG.id.charCodeAt(p++));
idB[i] = h << 4 | hex(c);
}
const [SZ0, SZ1, SZ2, SZ3, SZ4, SZ5, SZ6, SZ7, SZ8, SZ9, SZ10, SZ11, SZ12, SZ13, SZ14, SZ15] = idB;

const matchID = c =>
c[1] === SZ0 && c[2] === SZ1 && c[3] === SZ2 && c[4] === SZ3 &&
c[5] === SZ4 && c[6] === SZ5 && c[7] === SZ6 && c[8] === SZ7 &&
c[9] === SZ8 && c[10] === SZ9 && c[11] === SZ10 && c[12] === SZ11 &&
c[13] === SZ12 && c[14] === SZ13 && c[15] === SZ14 && c[16] === SZ15;

// =====================================================================
// 🛡️ 核心：双协议急速解析器
// =====================================================================
const parseHeader = (c, hasSSPass) => {
if (c.length < 7) return null;
const proto = c[0];
let host = '', port = 0, offset = 0;

if (proto === 0) {
if (c.length < 24 || !matchID(c)) return null;
const optLen = c[17];
const cmdPos = 18 + optLen;
if (cmdPos >= c.length || c[cmdPos] !== 1) return null;
if (cmdPos + 4 > c.length) return null;
port = (c[cmdPos + 1] << 8) | c[cmdPos + 2];
const addrType = c[cmdPos + 3];
let addrPos = cmdPos + 4;

if (addrType === 1) {
if (c.length < addrPos + 4) return null;
host = `${c[addrPos]}.${c[addrPos+1]}.${c[addrPos+2]}.${c[addrPos+3]}`;
offset = addrPos + 4;
} else if (addrType === 2) {
if (c.length < addrPos + 1) return null;
const len = c[addrPos];
if (c.length < addrPos + 1 + len) return null;
host = dec.decode(c.subarray(addrPos + 1, addrPos + 1 + len));
offset = addrPos + 1 + len;
} else if (addrType === 3) {
if (c.length < addrPos + 16) return null;
const ipv6 = [];
for (let i = 0; i < 8; i++) ipv6.push(((c[addrPos + i*2] << 8) | c[addrPos + i*2 + 1]).toString(16));
host = ipv6.join(':');
offset = addrPos + 16;
} else return null;
return { host, port, offset, isVless: true };

} else if (proto === 1 || proto === 3 || proto === 4) {
if (!hasSSPass) return null;

if (proto === 1) {
host = `${c[1]}.${c[2]}.${c[3]}.${c[4]}`;
port = (c[5] << 8) | c[6];
offset = 7;
} else if (proto === 3) {
const len = c[1];
if (c.length < 4 + len) return null;
host = dec.decode(c.subarray(2, 2 + len));
port = (c[2 + len] << 8) | c[3 + len];
offset = 4 + len;
} else {
if (c.length < 19) return null;
const ipv6 = [];
for (let i = 0; i < 8; i++) ipv6.push(((c[1 + i*2] << 8) | c[2 + i*2]).toString(16));
host = ipv6.join(':');
port = (c[17] << 8) | c[18];
offset = 19;
}
return { host, port, offset, isVless: false };
}

return null;
};

// =====================================================================
// 🏎️ 引擎配件：队列与下行聚合
// =====================================================================
const mkQ = (cap, qCap = cap, itemsMax = Math.max(1, qCap >> 8)) => {
let q = [], h = 0, qB = 0, buf = null;
const trim = () => { h > 32 && h * 2 >= q.length && (q = q.slice(h), h = 0); };
const take = () => { if (h >= q.length) return null; const d = q[h]; q[h++] = undefined; qB -= d.byteLength; trim(); return d; };
return { get bytes() { return qB; }, get size() { return q.length - h; }, get empty() { return h >= q.length; }, clear() { q = []; h = 0; qB = 0; },
sow(d) { const n = d?.byteLength || 0; if (!n) return 1; if (qB + n > qCap || q.length - h >= itemsMax) return 0; q.push(d); qB += n; return 1; },
bundle(d) {
d ||= take(); if (!d || h >= q.length || d.byteLength >= cap) return [d, 0];
let n = d.byteLength, e = h; while (e < q.length) { const x = q[e], nn = n + x.byteLength; if (nn > cap) break; n = nn; e++; }
if (e === h) return [d, 0]; const out = buf ||= new Uint8Array(cap); out.set(d);
for (let o = d.byteLength; h < e;) { const x = q[h]; q[h++] = undefined; qB -= x.byteLength; out.set(x, o); o += x.byteLength; } trim(); return [out.subarray(0, n), 1]; } }; };

const mkDn = w => {
const cap = CFG.dnPack, tail = CFG.dnTail, low = Math.max(4096, tail << 3);
let pb = new Uint8Array(cap), p = 0, tp = 0, mq = 0, gen = 0, qk = 0, qr = 0;
const reap = () => { tp && clearTimeout(tp); tp = 0; mq = 0; if (!p) return; w.send(pb.subarray(0, p).slice()); pb = new Uint8Array(cap); p = 0; qr = 0; };
const ripen = () => { if (tp || mq) return; mq = 1; qk = gen; queueMicrotask(() => { mq = 0; if (!p || tp) return; if (cap - p < tail) return reap(); tp = setTimeout(() => { tp = 0; if (!p) return; if (cap - p < tail) return reap(); if (qr < 2 && (gen !== qk || p < low)) { qr++; qk = gen; return ripen(); } reap(); }, Math.max(CFG.dnMs, 1)); }); };
return { send(u) { let o = 0, n = u?.byteLength || 0; if (!n) return; while (o < n) { if (!p && n - o >= cap) { const m = Math.min(cap, n - o); w.send(o || m !== n ? u.subarray(o, o + m) : u); o += m; continue; } const m = Math.min(cap - p, n - o); pb.set(u.subarray(o, o + m), p); p += m; o += m; gen++; if (p === cap || cap - p < tail) reap(); else ripen(); } }, reap }; };

const mill = async (rd, w) => {
const r = rd.getReader({ mode: 'byob' }), tx = mkDn(w); let buf = new ArrayBuffer(CFG.chunk);
let loopCount = 0;
try {
for (;;) {
const { done, value: v } = await r.read(new Uint8Array(buf, 0, CFG.chunk));
if (done) break;
if (!v?.byteLength) continue;
if (v.byteLength >= (CFG.chunk >> 1)) {
tx.reap(); tx.send(v.slice()); buf = new ArrayBuffer(CFG.chunk);
} else {
tx.send(v.slice()); buf = v.buffer;
}
if (++loopCount > 128) { loopCount = 0; await new Promise(queueMicrotask); }
}
tx.reap();
} catch {} finally { try { tx.reap(); } catch {} try { r.releaseLock(); } catch {} }
};

// =====================================================================
// 🛡️ 智能导航：动态地址获取 + 防雪崩池 + 兜底引擎
// =====================================================================
const 地址合法正则 = /^[a-zA-Z0-9._\-:[\]]+$/;
const 路径IP正则 = /^\/ip=([^&\/]+)/;

function 校验候选地址(候选地址) {
if (!候选地址 || 候选地址.length > 253 || 候选地址 === '.' || 候选地址 === '[]' || 候选地址 === '..' || 候选地址.startsWith('./') || 候选地址.startsWith('../') || 候选地址.startsWith(':') || !地址合法正则.test(候选地址)) { return 默认备用小可爱地址; }
return 候选地址;
}

const txt缓存池 = new Map();
const txt请求池 = new Map();

async function 获取动态地址(输入参数) {
if (!输入参数.includes('://') && !输入参数.includes('/')) return 校验候选地址(输入参数);
const 链接 = 输入参数.startsWith('http') ? 输入参数 : 'https://' + 输入参数;
const 当前时间 = Date.now();
const 缓存 = txt缓存池.get(链接);
if (缓存 && 当前时间 < 缓存.过期时间) return 缓存.目标地址;

let req = txt请求池.get(链接);
if (!req) {
req = (async () => {
try {
const 响应 = await fetch(链接, { headers: { 'User-Agent': 'Mozilla/5.0' }, cf: { cacheTtl: 60 } });
if (响应.ok) {
const 文本 = await 响应.text();
const 校验结果 = 校验候选地址(文本.replace(/[\r\n\s\uFEFF]/g, ''));
if (校验结果 !== 默认备用小可爱地址) {
txt缓存池.set(链接, { 目标地址: 校验结果, 过期时间: Date.now() + txt缓存生存期ms });
return 校验结果;
}
}
} catch (e) {}
txt缓存池.set(链接, { 目标地址: 默认备用小可爱地址, 过期时间: Date.now() + txt失败缓存生存期ms });
return 默认备用小可爱地址;
})();
txt请求池.set(链接, req);
req.finally(() => txt请求池.delete(链接));
}

return await req;
}

// 裸 IPv6（无方括号）含多个冒号会被识别为纯主机名，端口使用目标默认端口。
// 如需指定端口，请用 [2001:db8::1]:端口 格式。
function 拆分地址和端口(地址字符串, 默认端口) {
const 校验 = p => (Number.isInteger(p) && p >= 1 && p <= 65535 ? p : 默认端口);
if (地址字符串.startsWith('[')) {
const 括号结束 = 地址字符串.indexOf(']');
if (括号结束 === -1) return { 备用主机: 地址字符串, 备用端口: 默认端口 };
return { 备用主机: 地址字符串.slice(0, 括号结束 + 1), 备用端口: 校验(Number(地址字符串.slice(括号结束 + 2))) };
}
const 冒号位 = 地址字符串.lastIndexOf(':');
if (冒号位 === -1 || 地址字符串.indexOf(':') !== 冒号位) return { 备用主机: 地址字符串, 备用端口: 默认端口 };
return { 备用主机: 地址字符串.slice(0, 冒号位), 备用端口: 校验(Number(地址字符串.slice(冒号位 + 1))) };
}

const sprout = (f, h, p, s = f.connect({ hostname: h, port: p })) => s.opened.then(() => s);
const raceSprout = (f, h, p) => {
if (!f?.connect) return Promise.reject(new Error('connect unavailable'));
if (CFG.concur <= 1) return sprout(f, h, p);
const ts = Array.from({ length: CFG.concur }, () => sprout(f, h, p));
return Promise.any(ts).then(w => { ts.forEach(t => t.then(s => s !== w && s.close(), () => {})); return w; });
};

async function 带超时的并发抢答引擎(fetcher, 主机, 端口, 超时ms) {
let 炸弹定时器;
const 超时炸弹 = new Promise((_, reject) => { 炸弹定时器 = setTimeout(() => reject(new Error('连接超时')), 超时ms); });
try { return await Promise.race([raceSprout(fetcher, 主机, 端口), 超时炸弹]); }
finally { clearTimeout(炸弹定时器); }
}

// =====================================================================
// 🛸 核心调度器 (微任务收割机 + 双协议兼容)
// =====================================================================
const ws = async (req, 当前备用地址, 携带SS通行证) => {
const [client, server] = Object.values(new WebSocketPair());
server.accept({ allowHalfOpen: true }); server.binaryType = 'arraybuffer';
const fetcher = req.fetcher;
const edStr = req.headers.get('sec-websocket-protocol');
const ed = edStr && edStr.length <= CFG.maxED * 4 / 3 + 4 ? /** @type {*} */ (Uint8Array).fromBase64(edStr, { alphabet: 'base64url' }) : null;
let curW = null, sock = null, closed = false, busy = false;
const uq = mkQ(CFG.upPack, CFG.upQMax, CFG.upQMax >> 8);
const wither = () => { if (closed) return; closed = true; uq.clear(); try { curW?.releaseLock(); } catch {} try { sock?.close(); } catch {} try { server.close(); } catch {} };
const toU8 = d => { if (!d) return new Uint8Array(0); return d instanceof Uint8Array ? d : ArrayBuffer.isView(d) ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength) : new Uint8Array(d); };
const sow = d => { const u = toU8(d), n = u.byteLength; if (!n) return 1; if (uq.sow(u)) return 1; wither(); return 0; };

const tryConnect = async (host, port) => {
try { return await 带超时的并发抢答引擎(fetcher, host, port, 主连接超时毫秒); } catch {}
const { 备用主机: h2, 备用端口: p2 } = 拆分地址和端口(当前备用地址, port);
if (h2) try { return await 带超时的并发抢答引擎(fetcher, h2, p2, 备用连接超时毫秒); } catch {}
if (当前备用地址 !== 默认备用小可爱地址) {
const { 备用主机: h3, 备用端口: p3 } = 拆分地址和端口(默认备用小可爱地址, port);
if (h3) try { return await 带超时的并发抢答引擎(fetcher, h3, p3, 备用连接超时毫秒); } catch {}
}
return null;
};

const thresh = async () => { if (busy || closed) return; busy = true; try { for (;;) {
if (closed) break;
if (!sock) {
const [d] = uq.bundle(); if (!d) break;
const r = parseHeader(d, 携带SS通行证);
if (!r) { wither(); break; }
if (r.isVless) server.send(new Uint8Array([d[0], 0]));
const host = r.host, port = r.port, payload = d.subarray(r.offset);
sock = await tryConnect(host, port);
if (!sock) { wither(); break; }
curW = sock.writable.getWriter();
const [first] = uq.bundle(payload);
first?.byteLength && await curW.write(first);
mill(sock.readable, server).finally(() => wither());
continue;
}
const [d] = uq.bundle(); if (!d) break; await curW.write(d);
} } catch { wither(); } finally { busy = false; !uq.empty && !closed && queueMicrotask(thresh); } };

if (ed && sow(ed)) thresh();
server.addEventListener('message', e => { closed || (sow(e.data) && thresh()); });
server.addEventListener('close', () => wither()); server.addEventListener('error', () => wither());
return new Response(null, { status: 101, webSocket: client, headers: { 'Sec-WebSocket-Extensions': '' } });
};

// =====================================================================
// 📍 入口（Workers 版：含 ctx.waitUntil 保护子请求 + 模块级预热）
// =====================================================================
export default {
async fetch(req, env, ctx) {
if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
const 网址 = new URL(req.url);
const 携带SS通行证 = 网址.pathname.includes(CFG.id);

let 候选地址 = 默认备用小可爱地址;
if (网址.searchParams.has('ip')) {
候选地址 = 网址.searchParams.get('ip');
} else {
const 提取路径IP = 网址.pathname.match(路径IP正则);
if (提取路径IP) 候选地址 = decodeURIComponent(提取路径IP[1]);
}

// 预热：触发后续 Worker 实例的缓存预取（非阻塞）
_预热地址(候选地址);

// waitUntil 保护：即使客户端提前断开，也确保 TXT fetch 能完成并写入缓存
// 解决高压测速时 "Network connection lost / outcome: canceled" 问题
const 地址Promise = 获取动态地址(候选地址);
ctx.waitUntil(地址Promise);
const 当前备用地址 = await 地址Promise;

return ws(req, 当前备用地址, 携带SS通行证);
}

return new Response('Not Found', { status: 404 });
},
};
