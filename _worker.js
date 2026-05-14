const 小可爱文字解码器 = new TextDecoder('utf-8');
const 关门原因编码器 = new TextEncoder();
const 关门原因解码器 = new TextDecoder();
const 我的小甜甜身份证 = '88888888-8888-8888-8888-888888888888';
const 身份证字节 = ((uuid) => {
  const hex = uuid.replace(/-/g, '');
  const arr = new Uint8Array(16);
  for (let i = 0; i < 16; i++) arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return arr;
})(我的小甜甜身份证);
const [SZ0, SZ1, SZ2, SZ3, SZ4, SZ5, SZ6, SZ7, SZ8, SZ9, SZ10, SZ11, SZ12, SZ13, SZ14, SZ15] = 身份证字节;
const 默认备用小可爱地址 = 'usip.vpndns.net';  //兜底落地IP

const 合包最大字节       = 256 * 1024;
const 合包刷新阈值       = 192 * 1024;
const 合包最大等待       = 8;
const 桥梁缓冲水位       = 4 * 1024 * 1024;
const 主连接超时毫秒     = 2000;
const 备用连接超时毫秒   = 4000;
const 背压最大退避毫秒   = 16;
const 消息队列条数上限 = 512;
const 消息队列字节上限 = 64 * 1024 * 1024;

const 地址合法正则 = /^[a-zA-Z0-9._\-:\[\]]+$/;
const 路径IP正则 = /^\/ip=([^&\/]+)/;
const 握手确认包 = new Uint8Array([0, 0]);

function 截断关门原因(原因) {
  if (原因.length * 3 <= 123) return 原因;
  const encoded = 关门原因编码器.encode(原因);
  if (encoded.byteLength <= 123) return 原因;
  let len = 123;
  while (len > 0 && (encoded[len] & 0xc0) === 0x80) len--;
  return 关门原因解码器.decode(encoded.subarray(0, len));
}

function 校验候选地址(候选地址) {
  if (
    !候选地址 ||
    候选地址.length === 0 ||
    候选地址.length > 253 ||
    候选地址 === '.' ||
    候选地址 === '[]' ||
    候选地址 === '..' ||
    候选地址.startsWith('./') ||
    候选地址.startsWith('../') ||
    候选地址.startsWith(':') ||
    !地址合法正则.test(候选地址)
  ) {
    return 默认备用小可爱地址;
  }
  return 候选地址;
}

const txt缓存池 = new Map();
const txt请求池 = new Map();
const txt缓存生存期ms = 60 * 1000;
const txt失败冷却ms = 10 * 1000;

async function 获取动态地址(输入参数) {
  if (!输入参数 || (!输入参数.includes('://') && !输入参数.includes('/'))) {
    return 校验候选地址(输入参数 || 默认备用小可爱地址);
  }

  const 链接 = 输入参数.startsWith('http://') || 输入参数.startsWith('https://') ? 输入参数 : 'https://' + 输入参数;
  const 当前时间 = Date.now();
  const 缓存 = txt缓存池.get(链接);
  if (缓存 && 当前时间 < 缓存.过期时间) return 缓存.目标地址;

  if (txt请求池.has(链接)) return txt请求池.get(链接);

  const 请求Promise = (async () => {
    try {
      const 响应 = await fetch(链接, {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
        cf: { cacheTtl: 60 }
      });
      if (响应.ok) {
        let 文本 = await 响应.text();
        文本 = 文本.replace(/[\r\n\s\uFEFF]/g, '');
        const 校验结果 = 校验候选地址(文本);
        if (校验结果 !== 默认备用小可爱地址) {
          txt缓存池.set(链接, { 目标地址: 校验结果, 过期时间: Date.now() + txt缓存生存期ms });
          return 校验结果;
        }
        const 回退无效 = 缓存 ? 缓存.目标地址 : 默认备用小可爱地址;
        txt缓存池.set(链接, { 目标地址: 回退无效, 过期时间: Date.now() + txt失败冷却ms });
        return 回退无效;
      }
    } catch {}

    const 回退地址 = 缓存 ? 缓存.目标地址 : 默认备用小可爱地址;
    txt缓存池.set(链接, { 目标地址: 回退地址, 过期时间: Date.now() + txt失败冷却ms });
    return 回退地址;
  })().finally(() => txt请求池.delete(链接));

  txt请求池.set(链接, 请求Promise);
  return 请求Promise;
}

const _u16 = (b, o=0) => (b[o]<<8)|b[o+1];
const _pad4 = n => -n & 3;
const _cat = (...a) => { const r=new Uint8Array(a.reduce((s,x)=>s+x.length,0)); a.reduce((o,x)=>(r.set(x,o),o+x.length),0); return r; };
const _safeClose = (...a) => a.forEach(x => { try { x?.close?.(); } catch {} });
const _tid = () => crypto.getRandomValues(new Uint8Array(12));
const STUN_MAGIC = new Uint8Array([0x21,0x12,0xA4,0x42]);
const MT = { AQ:0x003,RQ:0x004,AO:0x103,AE:0x113,PQ:0x008,PO:0x108,CQ:0x00A,CO:0x10A,BQ:0x00B,BO:0x10B };
const AT = { USER:0x006,MI:0x008,ERR:0x009,PEER:0x012,REALM:0x014,NONCE:0x015,TRANSPORT:0x019,CONNID:0x02A };
const _stunAttr = (t, v) => { const b=new Uint8Array(4+v.length+_pad4(v.length)),d=new DataView(b.buffer); d.setUint16(0,t); d.setUint16(2,v.length); b.set(v,4); return b; };
const _stunMsg = (t, id, a) => { const bd=_cat(...a),h=new Uint8Array(20),d=new DataView(h.buffer); d.setUint16(0,t); d.setUint16(2,bd.length); h.set(STUN_MAGIC,4); h.set(id,8); return _cat(h,bd); };
const _expandIPv6 = ip => { ip=ip.replace(/^\[|\]$/g,'').split('%')[0]; if (!ip.includes('::')) return ip.split(':').map(g=>g||'0'); const [l,r]=ip.split('::'); const lp=l?l.split(':'):[],rp=r?r.split(':'):[]; return [...lp,...Array(8-lp.length-rp.length).fill('0'),...rp]; };
const _xorPeer = (ip, port) => { const v6=ip.includes(':'),b=new Uint8Array(v6?20:8),dv=new DataView(b.buffer); b[1]=v6?2:1; dv.setUint16(2,port^0x2112); if(v6){const xk=new Uint8Array(16);xk.set(STUN_MAGIC);_expandIPv6(ip).forEach((g,i)=>{const v=parseInt(g||'0',16);b[4+i*2]=((v>>8)^xk[i*2])&0xff;b[5+i*2]=(v&0xff)^xk[i*2+1];});}else{ip.split('.').forEach((v,i)=>b[4+i]=+v^STUN_MAGIC[i]);}return b; };
const _parseStun = d => { if(d.length<20||STUN_MAGIC.some((v,i)=>d[4+i]!==v))return null; const dv=new DataView(d.buffer,d.byteOffset,d.byteLength),ml=dv.getUint16(2),attrs={}; for(let o=20;o+4<=20+ml;){const t=dv.getUint16(o),l=dv.getUint16(o+2);if(o+4+l>d.length)break;attrs[t]=d.slice(o+4,o+4+l);o+=4+l+_pad4(l);}return{type:dv.getUint16(0),attrs}; };
const _parseErr = d => d?.length>=4?(d[2]&7)*100+d[3]:0;
const _addIntegrity = async (m,key) => { const c=new Uint8Array(m),d=new DataView(c.buffer);d.setUint16(2,d.getUint16(2)+24);const k=await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-1'},false,['sign']);return _cat(c,_stunAttr(AT.MI,new Uint8Array(await crypto.subtle.sign('HMAC',k,c)))); };
const _md5 = async s => new Uint8Array(await crypto.subtle.digest('MD5',关门原因编码器.encode(s)));
const _readStun = async (rd, buf) => { let b=buf??new Uint8Array(0); const pull=async()=>{const{done,value}=await rd.read();if(done)throw 0;b=_cat(b,new Uint8Array(value));}; try{while(b.length<20)await pull();const n=20+_u16(b,2);while(b.length<n)await pull();return[_parseStun(b.subarray(0,n)),b.length>n?b.subarray(n):null];}catch{return[null,null];}};
const _dnsCache = new Map();
const _resolveIP = async h => { if(/^\d+\.\d+\.\d+\.\d+$/.test(h))return h; if(h.includes(':'))return h.replace(/^\[|\]$/g,''); const now=Date.now(),c=_dnsCache.get(h);if(c&&now<c.exp)return c.ip; const doh=t=>fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(h)}&type=${t}`,{headers:{Accept:'application/dns-json'}}).then(r=>r.json()).catch(()=>({})); const[ra,raaaa]=await Promise.all([doh('A'),doh('AAAA')]); const ip=ra.Answer?.find(r=>r.type===1)?.data??raaaa.Answer?.find(r=>r.type===28)?.data??null; if(ip)_dnsCache.set(h,{ip,exp:Date.now()+30000}); return ip; };
const _getTurn = url => { let u;try{u=decodeURIComponent(url);}catch{return null;} const m=u.match(/\/turn:\/\/([^?\s]*)/i);if(!m)return null; const t=m[1],at=t.lastIndexOf('@'),cred=at>=0?t.slice(0,at):'',hp=t.slice(at+1); let host,portStr; if(hp.startsWith('[')){const e=hp.indexOf(']');if(e===-1)return null;host=hp.slice(0,e+1);portStr=hp.slice(e+2);}else{const ci=hp.lastIndexOf(':');host=ci>=0?hp.slice(0,ci):hp;portStr=ci>=0?hp.slice(ci+1):'';}; const port=+portStr;if(!port||port<1||port>65535)return null; const ci=cred.indexOf(':');return{host,port,user:ci>=0?cred.slice(0,ci):'',pass:ci>=0?cred.slice(ci+1):''}; };
const _turnAuth = async (w,r,transport,{user,pass},pipeline) => { const tp=new Uint8Array([transport,0,0,0]);await w.write(_stunMsg(MT.AQ,_tid(),[_stunAttr(AT.TRANSPORT,tp)]));let[msg,ex]=await _readStun(r);if(!msg)return null;let key=null,aa=[];const sign=m=>key?_addIntegrity(m,key):Promise.resolve(m);if(msg.type===MT.AE&&user&&_parseErr(msg.attrs[AT.ERR])===401){const realm=关门原因解码器.decode(msg.attrs[AT.REALM]??new Uint8Array(0)),nonce=msg.attrs[AT.NONCE]??new Uint8Array(0);key=await _md5(`${user}:${realm}:${pass}`);aa=[_stunAttr(AT.USER,关门原因编码器.encode(user)),_stunAttr(AT.REALM,关门原因编码器.encode(realm)),_stunAttr(AT.NONCE,nonce)];const aq=await _addIntegrity(_stunMsg(MT.AQ,_tid(),[_stunAttr(AT.TRANSPORT,tp),...aa]),key);const extras=pipeline?await Promise.all(pipeline(aa,sign)):[];await w.write(extras.length?_cat(aq,...extras):aq);[msg,ex]=await _readStun(r,ex);if(!msg)return null;}else if(pipeline&&msg.type===MT.AO){const extras=await Promise.all(pipeline(aa,sign));if(extras.length)await w.write(_cat(...extras));}return msg.type===MT.AO?{key,aa,ex,sign}:null; };
const _turnConn = async (fetcher, turn, targetIp, targetPort) => {
  let ctrl=null,data=null;
  const close=()=>_safeClose(ctrl,data);
  try {
    ctrl=await fetcher.connect({hostname:turn.host,port:turn.port});
    await ctrl.opened;
    const cw=ctrl.writable.getWriter(),cr=ctrl.readable.getReader();
    const peer=_stunAttr(AT.PEER,_xorPeer(targetIp,targetPort));
    const dataSocket=fetcher.connect({hostname:turn.host,port:turn.port});
    const auth=await _turnAuth(cw,cr,6,turn,(aa,sign)=>[sign(_stunMsg(MT.PQ,_tid(),[peer,...aa])),sign(_stunMsg(MT.CQ,_tid(),[peer,...aa]))]);
    if(!auth){try{cw.releaseLock();}catch{}try{cr.releaseLock();}catch{}close();return null;}
    const{aa,sign}=auth;let ex=auth.ex;
    let r;
    [r,ex]=await _readStun(cr,ex);if(r?.type!==MT.PO){try{cr.releaseLock();}catch{}try{cw.releaseLock();}catch{}close();return null;}
    [r,ex]=await _readStun(cr,ex);if(r?.type!==MT.CO||!r.attrs[AT.CONNID]){try{cr.releaseLock();}catch{}try{cw.releaseLock();}catch{}close();return null;}
    try{await dataSocket.opened;}catch{_safeClose(dataSocket);try{cr.releaseLock();}catch{}try{cw.releaseLock();}catch{}close();return null;}
    data=dataSocket;
    const dw=data.writable.getWriter(),dr=data.readable.getReader();
    await dw.write(await sign(_stunMsg(MT.BQ,_tid(),[_stunAttr(AT.CONNID,r.attrs[AT.CONNID]),...aa])));
    let extra;[r,extra]=await _readStun(dr);if(r?.type!==MT.BO){try{dw.releaseLock();}catch{}try{dr.releaseLock();}catch{}try{cr.releaseLock();}catch{}try{cw.releaseLock();}catch{}close();return null;}
    cr.releaseLock();cw.releaseLock();dw.releaseLock();
    let keepAliveDead=false;
    const closeAll=()=>{keepAliveDead=true;close();};
    const ctrlW=ctrl.writable.getWriter();
    (async()=>{try{const rd=ctrl.readable.getReader();while(!(await rd.read()).done);}catch{}})();
    (async()=>{try{for(;;){await new Promise(res=>setTimeout(res,270000));if(keepAliveDead)break;await ctrlW.write(_cat(await sign(_stunMsg(MT.RQ,_tid(),aa)),await sign(_stunMsg(MT.PQ,_tid(),[peer,...aa]))));}}catch{}})();
    const readable=new ReadableStream({
      type:'bytes',
      start(c){if(extra?.length)c.enqueue(extra.slice());},
      async pull(c){const bv=c.byobRequest?.view;if(bv){const{done,value}=await dr.read();if(done){c.close();c.byobRequest.respond(0);return;}const v=new Uint8Array(value),n=Math.min(v.byteLength,bv.byteLength);new Uint8Array(bv.buffer,bv.byteOffset,n).set(v.subarray(0,n));c.byobRequest.respond(n);if(n<v.byteLength)c.enqueue(v.subarray(n).slice());}else{const{done,value}=await dr.read();if(done){c.close();return;}c.enqueue(new Uint8Array(value));}},
      cancel(){dr.cancel();}
    });
    return{readable,writable:data.writable,close:closeAll};
  }catch{close();return null;}
};
const TURN_TIMEOUT = 3000;

export default {
  async fetch(来自外面的请求, env) {
    const 握手头 = 来自外面的请求.headers.get('Upgrade');
    if (握手头 && 握手头.toLowerCase() === 'websocket') {
      const 网址 = new URL(来自外面的请求.url);
      const 携带SS通行证 = 网址.pathname.includes(我的小甜甜身份证);

      const 早期数据头 = 来自外面的请求.headers.get('sec-websocket-protocol');
      let 早期数据 = null;
      if (早期数据头) {
        try {
          早期数据 = 解码base64url(早期数据头);
        } catch {}
      }

      let 候选地址 = 默认备用小可爱地址;
      if (网址.searchParams.has('ip')) {
        候选地址 = 网址.searchParams.get('ip') || 默认备用小可爱地址;
      } else {
        const 提取路径IP = 网址.pathname.match(路径IP正则);
        if (提取路径IP) 候选地址 = decodeURIComponent(提取路径IP[1]);
      }

      const 当前备用地址 = await 获取动态地址(候选地址);
      const turn小可爱 = _getTurn(来自外面的请求.url);
      return 升级成小可爱通道(来自外面的请求.fetcher, 当前备用地址, 携带SS通行证, 早期数据, turn小可爱);
    }
    return new Response('OK', { status: 200 });
  },
};

const _b64表 = (() => {
  const t = new Uint8Array(128);
  const _chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (let i = 0; i < 64; i++) t[_chars.charCodeAt(i)] = i;
  t['-'.charCodeAt(0)] = 62;
  t['_'.charCodeAt(0)] = 63;
  return t;
})();

function 解码base64url(str) {
  const 去等号 = str.replace(/=/g, '');
  const 长度 = 去等号.length;
  const 输出长度 = (长度 * 3 >> 2) - (str.endsWith('==') ? 2 : str.endsWith('=') ? 1 : 0);
  const 结果 = new Uint8Array(输出长度);
  let 写指针 = 0;
  const _lookup = (idx) => { const cc = 去等号.charCodeAt(idx); return cc < 128 ? (_b64表[cc] ?? 0) : 0; };

  for (let i = 0; i < 长度; i += 4) {
    const a = _lookup(i);
    const b = _lookup(i + 1);
    const c = i + 2 < 长度 ? _lookup(i + 2) : 0;
    const d = i + 3 < 长度 ? _lookup(i + 3) : 0;
    const n = (a << 18) | (b << 12) | (c << 6) | d;
    if (写指针 < 输出长度) 结果[写指针++] = n >> 16;
    if (写指针 < 输出长度) 结果[写指针++] = (n >> 8) & 0xff;
    if (写指针 < 输出长度) 结果[写指针++] = n & 0xff;
  }

  return 结果;
}


function 升级成小可爱通道(fetcher, 当前备用地址, 携带SS通行证, 早期数据, turn小可爱) {
  const 泡泡对 = new WebSocketPair();
  const 小甜甜端 = 泡泡对[0];
  const 服务端 = 泡泡对[1];
  服务端.accept();
  服务端.binaryType = 'arraybuffer';
  开启数据小火车(fetcher, 服务端, 当前备用地址, 携带SS通行证, 早期数据, turn小可爱).catch((e) => { console.error('[小火车]', e); });
  return new Response(null, {
    status: 101,
    webSocket: 小甜甜端,
    headers: { 'Sec-WebSocket-Extensions': '' }
  });
}

async function 开启数据小火车(fetcher, 服务端, 当前备用地址, 携带SS通行证, 早期数据, turn小可爱) {
  let 小火车TCP通道;
  let 已经关门了 = false;
  let 流控制器;

  const ws可读流 = new ReadableStream({
    start(c) { 流控制器 = c; },
    cancel(reason) { 关门谢客(1011, reason?.message ?? 'stream cancelled'); },
  }, new ByteLengthQueuingStrategy({ highWaterMark: 桥梁缓冲水位 }));

  let 启动传输的信号;
  let 启动失败的信号;
  const 等待启动信号 = new Promise((resolve, reject) => {
    启动传输的信号 = resolve;
    启动失败的信号 = reject;
  });

  let 中止控制器 = null;

  function 关门谢客(代码 = 1011, 原因 = '再见啦', WS已先关闭 = false) {
    if (已经关门了) return;
    已经关门了 = true;

    if (!WS已先关闭) {
      try { 服务端.close(代码, 截断关门原因(原因)); } catch {}
    }

    if (代码 !== 1000 || 启动失败的信号) {
      const 关门错误 = new Error(原因);
      try { 流控制器?.error(关门错误); } catch {}
      try { 启动失败的信号?.(关门错误); } catch {}
    }

    try { 中止控制器?.abort(); } catch {}
    try { 小火车TCP通道?.close?.(); } catch {}
  }

  async function 带超时的连接(主机, 端口, 超时ms) {
    if (已经关门了) throw new Error('已关门');
    let 炸弹定时器;
    const 通道 = fetcher.connect({ hostname: 主机, port: 端口 });
    通道.opened.catch(() => {});
    const 超时炸弹 = new Promise((_, reject) => {
      炸弹定时器 = setTimeout(() => reject(new Error('连接超时')), 超时ms);
    });
    try {
      await Promise.race([通道.opened, 超时炸弹]);
      return 通道;
    } catch (错误) {
      try { 通道.close(); } catch {}
      throw 错误;
    } finally {
      clearTimeout(炸弹定时器);
    }
  }

  服务端.addEventListener('close', () => 关门谢客(1000, '客户端挥手再见', true));
  服务端.addEventListener('error', () => 关门谢客(1011, 'WS出错啦', true));

  let 是第一个糖果包 = true;
  let 正在处理消息 = false;
  const 消息待办队列 = [];
  let 消息队列当前字节 = 0;
  let 消息队列读指针 = 0;

  const 触发消息处理 = () => {
    if (已经关门了 || 正在处理消息) return;
    正在处理消息 = true;
    (async () => {
      let 退避ms = 1;
      while (消息队列读指针 < 消息待办队列.length) {
        if (已经关门了) break;
        const 当前数据 = 消息待办队列[消息队列读指针++];
        消息队列当前字节 = Math.max(0, 消息队列当前字节 - 当前数据.byteLength);
        if (消息队列读指针 >= 64) {
          消息待办队列.splice(0, 消息队列读指针);
          消息队列读指针 = 0;
        }

        try {
          if (是第一个糖果包) {
            是第一个糖果包 = false;
            await 解读第一个糖果包(当前数据);
          } else {
            while (流控制器.desiredSize !== null && 流控制器.desiredSize <= 0) {
              if (已经关门了) break;
              await new Promise((r) => setTimeout(r, 退避ms));
              退避ms = Math.min(退避ms * 2, 背压最大退避毫秒);
            }
            退避ms = 1;
            if (已经关门了) break;
            try {
              流控制器.enqueue(当前数据);
            } catch {
              关门谢客(1011, '流已关闭');
              break;
            }
          }
        } catch {
          if (!已经关门了) 关门谢客(1011, '糖果包处理失败');
          break;
        }
      }
      消息待办队列.length = 0;
      消息队列读指针 = 0;
      消息队列当前字节 = 0;
      正在处理消息 = false;
    })().catch(() => {
      消息待办队列.length = 0;
      消息队列读指针 = 0;
      消息队列当前字节 = 0;
      正在处理消息 = false;
      if (!已经关门了) 关门谢客(1011, '消息队列崩溃');
    });
  };

  if (早期数据 && 早期数据.byteLength > 0) {
    消息待办队列.push(早期数据);
    消息队列当前字节 += 早期数据.byteLength;
    触发消息处理();
  }

  服务端.addEventListener('message', (事件) => {
    if (已经关门了) return;
    if (typeof 事件.data === 'string') {
      关门谢客(1008, '不支持文本帧');
      return;
    }

    const 数据 = 事件.data instanceof ArrayBuffer ? new Uint8Array(事件.data) : new Uint8Array(事件.data.buffer, 事件.data.byteOffset, 事件.data.byteLength);
    const 帧字节 = 数据.byteLength;
    if (
      消息待办队列.length >= 消息队列条数上限 ||
      消息队列当前字节 + 帧字节 > 消息队列字节上限
    ) {
      关门谢客(1011, '消息队列溢出');
      return;
    }

    消息待办队列.push(数据);
    消息队列当前字节 += 帧字节;
    触发消息处理();
  });

  async function 解读第一个糖果包(糖果数据) {
    const 缓冲区 = 糖果数据.buffer;
    const 视图偏移 = 糖果数据.byteOffset;
    const 有效长度 = 糖果数据.byteLength;
    const 视图 = new DataView(缓冲区, 视图偏移, 有效长度);

    if (有效长度 < 7) { 关门谢客(1008, '糖果包太短了'); return; }

    const 协议首字节 = 视图.getUint8(0);
    let 目标地址 = '';
    let 目标端口 = 0;
    let 数据负载起始 = 0;

    if (协议首字节 === 0) {
      if (有效长度 < 24) { 关门谢客(1008, '糖果包太短了'); return; }
      if (!身份证匹配(视图, 1)) { 关门谢客(1008, '身份证不对哦'); return; }

      const 附加长度 = 视图.getUint8(17);
      const cmd字节位 = 18 + 附加长度;
      if (cmd字节位 >= 有效长度) { 关门谢客(1008, '糖果包太短了'); return; }

      const cmd = 视图.getUint8(cmd字节位);
      if (cmd !== 1) { 关门谢客(1008, '不支持的指令类型'); return; }

      const 端口起始位 = cmd字节位 + 1;
      if (端口起始位 + 2 > 有效长度) { 关门谢客(1008, '糖果包太短了'); return; }
      目标端口 = 视图.getUint16(端口起始位);
      if (目标端口 === 0) { 关门谢客(1008, '端口不合法'); return; }

      const 地址类型起始位 = 端口起始位 + 2;
      if (地址类型起始位 >= 有效长度) { 关门谢客(1008, '糖果包太短了'); return; }
      const 地址类型 = 视图.getUint8(地址类型起始位);
      let 地址字节长度 = 0;
      let 地址数据起始位 = 地址类型起始位 + 1;

      switch (地址类型) {
        case 1:
          if (地址数据起始位 + 4 > 有效长度) { 关门谢客(1008, '糖果包太短了'); return; }
          地址字节长度 = 4;
          目标地址 = `${视图.getUint8(地址数据起始位)}.${视图.getUint8(地址数据起始位 + 1)}.${视图.getUint8(地址数据起始位 + 2)}.${视图.getUint8(地址数据起始位 + 3)}`;
          break;
        case 2:
          if (地址数据起始位 >= 有效长度) { 关门谢客(1008, '糖果包太短了'); return; }
          地址字节长度 = 视图.getUint8(地址数据起始位);
          if (地址字节长度 === 0) { 关门谢客(1008, '地址为空'); return; }
          if (地址字节长度 > 253) { 关门谢客(1008, '域名过长'); return; }
          地址数据起始位 += 1;
          if (地址数据起始位 + 地址字节长度 > 有效长度) { 关门谢客(1008, '糖果包太短了'); return; }
          try {
            目标地址 = 小可爱文字解码器.decode(new Uint8Array(缓冲区, 视图偏移 + 地址数据起始位, 地址字节长度));
          } catch {
            关门谢客(1008, '域名解码失败');
            return;
          }
          break;
        case 3: {
          if (地址数据起始位 + 16 > 有效长度) { 关门谢客(1008, '糖果包太短了'); return; }
          地址字节长度 = 16;
          const b = 地址数据起始位;
          目标地址 =
            视图.getUint16(b).toString(16) + ':' +
            视图.getUint16(b + 2).toString(16) + ':' +
            视图.getUint16(b + 4).toString(16) + ':' +
            视图.getUint16(b + 6).toString(16) + ':' +
            视图.getUint16(b + 8).toString(16) + ':' +
            视图.getUint16(b + 10).toString(16) + ':' +
            视图.getUint16(b + 12).toString(16) + ':' +
            视图.getUint16(b + 14).toString(16);
          break;
        }
        default:
          关门谢客(1008, '不认识的地址类型');
          return;
      }

      数据负载起始 = 地址数据起始位 + 地址字节长度;
      try { 服务端.send(握手确认包); } catch {}
    } else if (协议首字节 === 1 || 协议首字节 === 3 || 协议首字节 === 4) {
      if (!携带SS通行证) { 关门谢客(1008, '抓到一只没有通行证的野猫'); return; }

      switch (协议首字节) {
        case 1:
          if (有效长度 < 7) { 关门谢客(1008, 'SS-V4包太短'); return; }
          目标地址 = `${视图.getUint8(1)}.${视图.getUint8(2)}.${视图.getUint8(3)}.${视图.getUint8(4)}`;
          目标端口 = 视图.getUint16(5);
          数据负载起始 = 7;
          break;
        case 3: {
          const 域名长度 = 视图.getUint8(1);
          if (域名长度 === 0) { 关门谢客(1008, 'SS-域名为空'); return; }
          if (有效长度 < 4 + 域名长度) { 关门谢客(1008, 'SS-域名包太短'); return; }
          try {
            目标地址 = 小可爱文字解码器.decode(new Uint8Array(缓冲区, 视图偏移 + 2, 域名长度));
          } catch {
            关门谢客(1008, 'SS-域名解码失败');
            return;
          }
          目标端口 = 视图.getUint16(2 + 域名长度);
          数据负载起始 = 4 + 域名长度;
          break;
        }
        case 4: {
          if (有效长度 < 19) { 关门谢客(1008, 'SS-V6包太短'); return; }
          目标地址 = [
            视图.getUint16(1).toString(16), 视图.getUint16(3).toString(16),
            视图.getUint16(5).toString(16), 视图.getUint16(7).toString(16),
            视图.getUint16(9).toString(16), 视图.getUint16(11).toString(16),
            视图.getUint16(13).toString(16), 视图.getUint16(15).toString(16),
          ].join(':');
          目标端口 = 视图.getUint16(17);
          数据负载起始 = 19;
          break;
        }
        default:
          关门谢客(1008, '不支持的神秘星际语言');
          return;
      }
    } else {
      关门谢客(1008, '不支持的神秘星际语言');
      return;
    }

    if (目标端口 === 0 || 数据负载起始 > 有效长度) { 关门谢客(1008, '地址段越界'); return; }

    const 首包剩余长度 = 有效长度 - 数据负载起始;

    const tryConnect = async () => {
      if (turn小可爱) {
        let _t, _cancelled = false;
        const bomb = new Promise(res => { _t = setTimeout(() => { _cancelled = true; res(null); }, TURN_TIMEOUT); });
        const result = await Promise.race([
          (async () => {
            const ip = await _resolveIP(目标地址);
            if (!ip) return null;
            const ts = await _turnConn(fetcher, turn小可爱, ip, 目标端口);
            if (_cancelled && ts) { ts.close(); return null; }
            return ts;
          })(),
          bomb
        ]).finally(() => clearTimeout(_t));
        if (result) return result;
      }
      try { return await 带超时的连接(目标地址, 目标端口, 主连接超时毫秒); } catch {}
      try {
        const { 备用主机, 备用端口 } = 拆分地址和端口(当前备用地址, 目标端口);
        if (备用主机) return await 带超时的连接(备用主机, 备用端口, 备用连接超时毫秒);
      } catch {}
      if (当前备用地址 !== 默认备用小可爱地址) {
        try {
          const { 备用主机, 备用端口 } = 拆分地址和端口(默认备用小可爱地址, 目标端口);
          if (备用主机) return await 带超时的连接(备用主机, 备用端口, 备用连接超时毫秒);
        } catch {}
      }
      return null;
    };

    const 临时通道 = await tryConnect();
    if (!临时通道 || 已经关门了) {
      if (临时通道) try { 临时通道.close(); } catch {}
      关门谢客(1011, '所有路都堵死啦');
      return;
    }
    小火车TCP通道 = 临时通道;

    if (已经关门了) return;
    if (首包剩余长度 > 0) {
      try { 流控制器.enqueue(new Uint8Array(缓冲区, 视图偏移 + 数据负载起始, 首包剩余长度).slice()); } catch {}
    }

    启动传输的信号();
  }

  try {
    await 等待启动信号;
  } catch {
    return;
  }

  if (已经关门了) return;
  启动传输的信号 = null;
  启动失败的信号 = null;

  中止控制器 = new AbortController();
  const { signal: 中止信号 } = 中止控制器;

  await Promise.all([
    ws可读流.pipeTo(小火车TCP通道.writable, { signal: 中止信号 }).catch((e) => {
      if (e?.name !== 'AbortError') 关门谢客(1011, '桥梁→TCP中断');
    }),
    小火车TCP通道.readable.pipeTo(
      合包发送流(服务端, 合包最大字节, 合包刷新阈值, 合包最大等待),
      { signal: 中止信号 },
    ).catch((e) => {
      if (e?.name !== 'AbortError') 关门谢客(1011, 'TCP→WS异常');
    }),
  ]).catch(() => {});

  if (!已经关门了) 关门谢客(1000, '传输完成');
}

function 合包发送流(服务端, 最大字节, 刷新阈值, 最大等待ms) {
  const 积累缓冲 = [];
  let 积累字节数 = 0;
  let 定时器 = null;
  let 复用缓冲区 = new Uint8Array(最大字节);

  function 立刻发出去() {
    if (定时器) { clearTimeout(定时器); 定时器 = null; }
    if (积累缓冲.length === 0) return;
    if (服务端.readyState !== 1) {
      积累缓冲.length = 0;
      积累字节数 = 0;
      return;
    }

    let 合并包;
    if (积累缓冲.length === 1) {
      合并包 = 积累缓冲[0].slice();
    } else {
      if (积累字节数 > 复用缓冲区.byteLength) {
        复用缓冲区 = new Uint8Array(Math.max(最大字节, 积累字节数 * 2));
      } else if (积累字节数 < 复用缓冲区.byteLength >> 2 && 复用缓冲区.byteLength > 最大字节) {
        复用缓冲区 = new Uint8Array(Math.max(最大字节, 积累字节数));
      }
      let 写入位置 = 0;
      for (const 块 of 积累缓冲) {
        复用缓冲区.set(块, 写入位置);
        写入位置 += 块.byteLength;
      }
      合并包 = 复用缓冲区.subarray(0, 积累字节数).slice();
    }

    积累缓冲.length = 0;
    积累字节数 = 0;
    try { 服务端.send(合并包); } catch {}
  }

  return new WritableStream({
    write(chunk) {
      积累缓冲.push(chunk);
      积累字节数 += chunk.byteLength;
      if (积累字节数 >= 刷新阈值) {
        立刻发出去();
      } else if (!定时器) {
        定时器 = setTimeout(立刻发出去, 最大等待ms);
      }
    },
    flush() { 立刻发出去(); },
    abort() {
      if (定时器) { clearTimeout(定时器); 定时器 = null; }
      积累缓冲.length = 0;
      积累字节数 = 0;
    },
  }, new ByteLengthQueuingStrategy({ highWaterMark: 最大字节 }));
}

function 拆分地址和端口(地址字符串, 默认端口) {
  function 校验端口(端口) {
    return Number.isInteger(端口) && 端口 >= 1 && 端口 <= 65535 ? 端口 : 默认端口;
  }

  if (地址字符串.startsWith('[')) {
    const 括号结束 = 地址字符串.indexOf(']');
    if (括号结束 === -1) return { 备用主机: 地址字符串, 备用端口: 默认端口 };
    const 备用主机 = 地址字符串.slice(0, 括号结束 + 1);
    const 后缀 = 地址字符串.slice(括号结束 + 1);
    return {
      备用主机,
      备用端口: 校验端口(后缀.startsWith(':') ? Number(后缀.slice(1)) : 默认端口),
    };
  }

  const 冒号位 = 地址字符串.lastIndexOf(':');
  if (冒号位 === -1) return { 备用主机: 地址字符串, 备用端口: 默认端口 };
  if (地址字符串.indexOf(':') !== 冒号位) return { 备用主机: 地址字符串, 备用端口: 默认端口 };
  return {
    备用主机: 地址字符串.slice(0, 冒号位),
    备用端口: 校验端口(Number(地址字符串.slice(冒号位 + 1))),
  };
}

function 身份证匹配(视图, offset = 0) {
  return 视图.getUint8(offset) === SZ0 &&
    视图.getUint8(offset + 1) === SZ1 &&
    视图.getUint8(offset + 2) === SZ2 &&
    视图.getUint8(offset + 3) === SZ3 &&
    视图.getUint8(offset + 4) === SZ4 &&
    视图.getUint8(offset + 5) === SZ5 &&
    视图.getUint8(offset + 6) === SZ6 &&
    视图.getUint8(offset + 7) === SZ7 &&
    视图.getUint8(offset + 8) === SZ8 &&
    视图.getUint8(offset + 9) === SZ9 &&
    视图.getUint8(offset + 10) === SZ10 &&
    视图.getUint8(offset + 11) === SZ11 &&
    视图.getUint8(offset + 12) === SZ12 &&
    视图.getUint8(offset + 13) === SZ13 &&
    视图.getUint8(offset + 14) === SZ14 &&
    视图.getUint8(offset + 15) === SZ15;
}
