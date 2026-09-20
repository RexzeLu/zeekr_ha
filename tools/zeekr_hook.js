/*
 * zeekr_hook.js —— 极氪 App（com.zeekrlife.mobile）运行时密钥/令牌提取钩子
 *
 * 目标（按优先级）：
 *   1. 抓出签名共享密钥（GRIC 体系 x-signature 2.1 的密钥，或 SNC 体系 HttpSecretKey）
 *   2. 抓出「待签名字符串」（canonical string）—— 与密钥同时拿到才能确定算法
 *   3. 抓出 App 实际使用的 authorization 令牌身份（azp/iss/scope）
 *   4. 抓出完整请求（URL + 头 + 体），作为离线爆破规范串构造方式的素材
 *
 * 设计要点：
 *   - 运行时 hook 完全绕过 dex 加固：静态看不到的类，运行时都是明文。
 *   - 两条独立的取证路线：
 *       a) 通用加密 API（javax.crypto）—— 不依赖类名/方法名，只要能拿到密钥就必然经过这里；
 *       b) 类名扫描 —— 覆盖不走标准加密 API 的自研签名实现。
 *
 * 注：本文件由 tools/zeekr_frida.py 拼在 frida-tools 自带的 java.js 桥之后注入，
 *     依赖注入前的 `var Java = bridge;`（frida 17 起运行时不再内置 Java 桥）。
 */

'use strict';

var PKG = 'com.zeekrlife.mobile';
var seen = {};
var emitCount = 0;
var EMIT_CAP = 20000;
var lastHitsKey = '';
var lastNetKey = '';

function emit(kind, data) {
    if (emitCount >= EMIT_CAP) return;
    emitCount++;
    send({ kind: kind, data: data });
}

function once(scope, key) {
    var k = scope + '|' + key;
    if (seen[k]) return false;
    seen[k] = true;
    return true;
}

function safeString(v) {
    try {
        if (v === null || v === undefined) return null;
        return String(v);
    } catch (e) {
        return null;
    }
}

// frida 的 NativePointer.toString() 是十六进制（0x13），
// parseInt(x, 10) 遇到 0x 前缀会直接返回 0 —— 数字参数必须走这里。
function pint(p) {
    if (p === null || p === undefined) return 0;
    try {
        if (typeof p === 'number') return p | 0;
        if (typeof p.toInt32 === 'function') return p.toInt32();
        return parseInt(String(p), 0) || 0;
    } catch (e) {
        return 0;
    }
}

function looksLikeKey(s) {
    if (typeof s !== 'string') return false;
    if (s.length < 16 || s.length > 128) return false;
    if (/^[0-9a-fA-F]{32}$/.test(s)) return true;
    if (/^[0-9a-fA-F]{40}$/.test(s)) return true;
    if (/^[0-9a-fA-F]{64}$/.test(s)) return true;
    if (/^[A-Za-z0-9_\-]{32,96}$/.test(s) && !/^[\d.]+$/.test(s)) return true;
    return false;
}

/* ---------- 通用工具 ---------- */

// Java byte[] 元素是有符号的，必须归一化到 0..255
function bytesToHex(b) {
    var s = '';
    try {
        for (var i = 0; i < b.length; i++) {
            s += ('0' + ((b[i] + 256) % 256).toString(16)).slice(-2);
        }
    } catch (e) {
        return '<hex-err:' + e + '>';
    }
    return s;
}

function bytesToAscii(b) {
    var s = '';
    try {
        for (var i = 0; i < b.length; i++) {
            var v = (b[i] + 256) % 256;
            s += (v >= 32 && v < 127) ? String.fromCharCode(v) : '.';
        }
    } catch (e) {
        return '<ascii-err:' + e + '>';
    }
    return s;
}

var B64C = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function b64ToBytes(s) {
    s = String(s).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var out = [], buf = 0, bits = 0;
    for (var i = 0; i < s.length; i++) {
        var c = s.charAt(i);
        if (c === '=') break;
        var v = B64C.indexOf(c);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push((buf >> bits) & 0xff);
        }
    }
    return out;
}

function b64ToUtf8(s) {
    var bytes = b64ToBytes(s);
    var esc = '';
    for (var i = 0; i < bytes.length; i++) esc += '%' + ('0' + bytes[i].toString(16)).slice(-2);
    try {
        return decodeURIComponent(esc);
    } catch (e) {
        return null;
    }
}

function describeJwt(tok) {
    try {
        var parts = String(tok).split('.');
        if (parts.length < 3) return null;
        var p = JSON.parse(b64ToUtf8(parts[1]));
        var out = {
            azp: p.azp, aud: p.aud, iss: p.iss, sub: p.sub, userId: p.userId,
            brand: p.brand, env: p.env, scope: p.scope, exp: p.exp,
            token_len: String(tok).length,
            head: String(tok).slice(0, 24) + '...'
        };
        if (p.exp) {
            try { out.exp_readable = new Date(p.exp * 1000).toISOString(); } catch (e) { }
        }
        return out;
    } catch (e) {
        return null;
    }
}

/* ---------- 1. 通用加密 API：密钥 + 待签串（不依赖类名） ---------- */

function reportKey(api, bytesArr, alg) {
    try {
        var hex = bytesToHex(bytesArr);
        if (!once('key', hex)) return;
        emit('CRYPTO-KEY', {
            api: api,
            alg: safeString(alg),
            len: bytesArr.length,
            hex: hex,
            ascii: bytesToAscii(bytesArr)
        });
    } catch (e) {
        emit('hook-miss', 'reportKey ' + api + ': ' + e);
    }
}

function reportData(api, bytesArr, extra) {
    try {
        var hex = bytesToHex(bytesArr);
        if (!once('data', api + hex.slice(0, 160))) return;
        var d = {
            api: api,
            len: bytesArr.length,
            ascii: bytesToAscii(bytesArr).slice(0, 1200),
            hex_head: hex.slice(0, 400)
        };
        if (extra) {
            for (var k in extra) d[k] = extra[k];
        }
        emit('CRYPTO-DATA', d);
    } catch (e) {
        emit('hook-miss', 'reportData ' + api + ': ' + e);
    }
}

function hookCrypto() {
    var ok = [];

    // ---- SecretKeySpec：任何「用字节建对称密钥」的路径都会经过这里 ----
    try {
        var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
        SKS.$init.overload('[B', 'java.lang.String').implementation = function (key, alg) {
            reportKey('SecretKeySpec(byte[],String)', key, alg);
            return this.$init(key, alg);
        };
        SKS.$init.overload('[B', 'int', 'int', 'java.lang.String').implementation = function (key, off, len, alg) {
            reportKey('SecretKeySpec(byte[],int,int,String)', key, alg);
            return this.$init(key, off, len, alg);
        };
        ok.push('SecretKeySpec');
    } catch (e) {
        emit('hook-miss', 'SecretKeySpec: ' + e);
    }

    // ---- Mac：对称签名本体。doFinal 的入参就是待签名字节 ----
    try {
        var Mac = Java.use('javax.crypto.Mac');
        var algOf = function (mac) {
            try { return safeString(mac.getAlgorithm()); } catch (e) { return null; }
        };
        try {
            Mac.init.overload('java.security.Key').implementation = function (key) {
                try {
                    var enc = key.getEncoded();
                    if (enc) reportKey('Mac.init(' + safeString(key.getAlgorithm()) + ')', enc, key.getAlgorithm());
                } catch (e) { }
                return this.init(key);
            };
            ok.push('Mac.init');
        } catch (e) { }

        try {
            Mac.doFinal.overload('[B').implementation = function (input) {
                try {
                    reportData('Mac.doFinal[' + algOf(this) + ']', input, null);
                } catch (e) { }
                return this.doFinal(input);
            };
            ok.push('Mac.doFinal([B)');
        } catch (e) { }

        try {
            Mac.doFinal.overload().implementation = function () {
                try {
                    emit('CRYPTO-DATA', { api: 'Mac.doFinal[' + algOf(this) + ']', note: 'no-arg 累积式', len: 0 });
                } catch (e) { }
                return this.doFinal();
            };
            ok.push('Mac.doFinal()');
        } catch (e) { }
    } catch (e) {
        emit('hook-miss', 'Mac: ' + e);
    }

    // ---- MessageDigest：md5(body) 这类预处理 ----
    //   digest[..] 的「输出」本身已经是摘要，价值有限；
    //   真正要的是 update[..] 的「输入」—— 那才是待摘要的原文（多半就是待签串/拼串素材）。
    try {
        var MD = Java.use('java.security.MessageDigest');
        var mdCap = 0;

        var algOfMd = function (md) {
            try { return safeString(md.getAlgorithm()); } catch (e) { return null; }
        };

        // 输入侧：update(byte[]) —— 一次喂完整原文，最常见
        try {
            MD.update.overload('[B').implementation = function (buf) {
                try {
                    if (mdCap < 600 && buf && buf.length > 0 && buf.length < 16384) {
                        mdCap++;
                        reportData('MessageDigest.update[' + algOfMd(this) + ']', buf, null);
                    }
                } catch (e) { }
                return this.update(buf);
            };
            ok.push('MessageDigest.update([B)');
        } catch (e) {
            emit('hook-miss', 'MD.update([B): ' + e);
        }

        // 分片喂入（update(byte[],int,int)）；只记第一个分片，避免同一串被拆成多条
        try {
            MD.update.overload('[B', 'int', 'int').implementation = function (buf, off, len) {
                try {
                    if (mdCap < 600 && buf && len > 0) {
                        mdCap++;
                        var slice = null;
                        try { slice = Java.array('byte', buf); } catch (e) { slice = buf; }
                        var part = null;
                        try { part = Java.array('byte', []); } catch (e) { part = null; }
                        // 只取 [off, off+len)
                        var out = [];
                        try {
                            for (var i = 0; i < len && i < 16384; i++) out.push(buf[off + i]);
                            var ab = Java.array('byte', out);
                            reportData('MessageDigest.update[off,len][' + algOfMd(this) + ']', ab,
                                { off: off, total: buf.length });
                        } catch (e) {
                            reportData('MessageDigest.update[off,len][' + algOfMd(this) + ']', buf, { off: off, total: buf.length });
                        }
                    }
                } catch (e) { }
                return this.update(buf, off, len);
            };
            ok.push('MessageDigest.update([B,int,int)');
        } catch (e) { }

        // 输出侧：保留（用于把输入→输出配对，验证算法）
        MD.digest.overload('[B').implementation = function (input) {
            try {
                if (mdCap < 600 && input && input.length < 16384) {
                    mdCap++;
                    reportData('MessageDigest.digest[' + algOfMd(this) + ']', input, null);
                }
            } catch (e) { }
            return this.digest(input);
        };
        MD.digest.overload().implementation = function () {
            try {
                if (mdCap < 600) {
                    mdCap++;
                    emit('CRYPTO-DATA', { api: 'MessageDigest.digest[' + algOfMd(this) + ']', note: 'no-arg', len: 0 });
                }
            } catch (e) { }
            return this.digest();
        };
        ok.push('MessageDigest.digest');
    } catch (e) {
        emit('hook-miss', 'MessageDigest: ' + e);
    }

    // ---- Cipher：对称加解密本体。init 的 Key + doFinal 的明/密文一起拿 ----
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        try {
            Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
                try {
                    var kenc = null;
                    try { kenc = key.getEncoded(); } catch (e) { }
                    var line = 'Cipher.init ' + safeString(this.getAlgorithm()) +
                        ' mode=' + mode + ' keyAlg=' + safeString(key.getAlgorithm());
                    if (once('cip-init', line)) emit('CIPHER-INIT', line);
                    if (kenc) reportKey('Cipher.init(' + safeString(key.getAlgorithm()) + ')', kenc, key.getAlgorithm());
                } catch (e) { }
                return this.init(mode, key);
            };
            ok.push('Cipher.init');
        } catch (e) { }

        try {
            Cipher.doFinal.overload('[B').implementation = function (buf) {
                var res;
                try {
                    res = this.doFinal(buf);
                } catch (err) {
                    throw err;
                }
                try {
                    var a = safeString(this.getAlgorithm());
                    reportData('Cipher.in[' + a + ']', buf, null);
                    if (res) reportData('Cipher.out[' + a + ']', res, null);
                } catch (e) { }
                return res;
            };
            ok.push('Cipher.doFinal');
        } catch (e) { }
    } catch (e) {
        emit('hook-miss', 'Cipher: ' + e);
    }

    // ---- String/Base64：签名结果往往在这里成型 ----
    try {
        var B64 = Java.use('android.util.Base64');
        try {
            B64.encodeToString.overload('[B', 'int').implementation = function (buf, flags) {
                var r = this.encodeToString(buf, flags);
                try {
                    if (buf && buf.length >= 20 && buf.length <= 128) {
                        reportData('Base64.out', buf, { flags: flags, result: safeString(r) });
                    }
                } catch (e) { }
                return r;
            };
            ok.push('Base64.encodeToString');
        } catch (e) { }
    } catch (e) { }

    emit('hooked', 'crypto: ' + ok.join(', '));
}

/* ---------- 2. okhttp：完整请求转储 + 令牌身份 ---------- */

// 框架包前缀：类名扫描时排除，否则会捞进上千个 java.security.* 的 AOSP 噪声
var FRAMEWORK_RE = /^(java\.|javax\.|sun\.|android\.|com\.android\.|dalvik\.|gov\.nist\.|libcore\.|org\.apache\.|kotlin\.|kotlinx\.|org\.json\.|com\.google\.android\.|org\.chromium\.)/;

function isAppClass(n) {
    if (!n || n.charAt(0) === '[') return false;              // 数组类（[Lxxx;）没有可 hook 的方法
    if (/\$\$ExternalSyntheticLambda/.test(n)) return false;  // 编译器合成类
    return !FRAMEWORK_RE.test(n);
}

// 从已加载类里找出被重打包/混淆的网络栈类名（本 App 的 okhttp 已被混淆，
// 固定写 okhttp3.Request$Builder 会 ClassNotFoundException）
//
// 两手：
//   a) 按名字匹配 okhttp/okio 家族（重打包常见做法是保留类名、换包名，或整包改名）
//   b) 按「方法签名」反查 —— newCall / interceptor / addHeader 是 okhttp 的语义指纹，
//      类名被混淆也改不掉方法名（改了就接不上拦截器生态）
function findNetworkClasses(all) {
    var found = { builders: [], bodies: [], buffers: [], okfamily: [], byMethod: [] };
    for (var i = 0; i < all.length; i++) {
        var n = all[i];
        if (typeof n !== 'string' || n.charAt(0) === '[') continue;
        var ln = n.toLowerCase();

        if (/request\$builder$/.test(ln)) { if (isAppClass(n)) found.builders.push(n); continue; }
        if (/requestbody$/.test(ln)) { if (isAppClass(n)) found.bodies.push(n); continue; }

        if (ln.indexOf('okhttp') >= 0 || ln === 'okio.buffer' || ln.indexOf('okio.') === 0) {
            if (found.okfamily.length < 60) found.okfamily.push(n);
        }
    }
    return found;
}

function probeMethods(found) {
    // 反向指纹：谁能提供 newCall(...) / interceptor()，谁就是 okhttp 的门面
    var cands = found.okfamily.slice(0);
    for (var i = 0; i < cands.length; i++) {
        var n = cands[i];
        try {
            var C = Java.use(n);
            var ms = C.class.getDeclaredMethods();
            for (var j = 0; j < ms.length; j++) {
                var mn = ms[j].getName();
                if (mn === 'newCall' || mn === 'addInterceptor') {
                    found.byMethod.push(n + '#' + mn);
                }
            }
        } catch (e) { }
    }
    return found;
}

function hookOkHttp() {
    var all;
    try {
        all = Java.enumerateLoadedClassesSync();
    } catch (e) {
        return false;
    }
    var net = findNetworkClasses(all);
    net = probeMethods(net);
    var nk = net.builders.join(',') + '|' + net.bodies.join(',') + '|' +
        net.okfamily.join(',') + '|' + net.byMethod.join(',');
    if (nk !== lastNetKey) {
        lastNetKey = nk;
        emit('net-classes', net);
    }

    // 找 okio.Buffer 用于读出请求体（可能被重打包改名，所以在 okfamily 里顺带找 Buffer 类）
    var bufferName = null;
    for (var bi = 0; bi < net.okfamily.length; bi++) {
        if (net.okfamily[bi] === 'okio.Buffer') { bufferName = 'okio.Buffer'; break; }
    }
    if (!bufferName) {
        for (var bj = 0; bj < net.okfamily.length; bj++) {
            if (/\.buffer$/i.test(net.okfamily[bj])) { bufferName = net.okfamily[bj]; break; }
        }
    }

    var builderName = net.builders.length ? net.builders[0] : null;
    // 找不到 okhttp 的 Builder 也不能提前退出：下面的 URLConnection / 原生 SSL 钩子仍要装
    if (!builderName) return false;

    var RB;
    try {
        RB = Java.use(builderName);
    } catch (e) {
        emit('hook-miss', builderName + ': ' + e);
        return false;
    }

    // 2.1 build() 处做完整转储：URL + 方法 + 全部头 + 体
    try {
        RB.build.implementation = function () {
            var req = this.build();
            try {
                var url = safeString(req.url().toString());
                if (url && /zeekrlife|geely|snc-|gric|remoteControl|tsp/i.test(url)) {
                    var h = req.headers();
                    var n = h.size();
                    var lines = [];
                    var sig = '';
                    for (var i = 0; i < n; i++) {
                        var hn = safeString(h.name(i));
                        var hv = safeString(h.value(i));
                        lines.push(hn + ': ' + hv);
                        if (hn && hn.toLowerCase() === 'x-signature') sig = hv;
                    }
                    var bodyStr = null;
                    try {
                        var rb = req.body();
                        if (rb && bufferName) {
                            var Buf = Java.use(bufferName);
                            var buf = Buf.$new();
                            rb.writeTo(buf);
                            bodyStr = safeString(buf.readUtf8());
                        }
                    } catch (e) { }
                    var sigPart = sig ? (sig.length + ':' + sig.slice(0, 16)) : '';
                    if (once('req', url + '|' + sigPart + '|' + safeString(req.method()))) {
                        emit('FULL-REQUEST', {
                            cls: builderName,
                            method: safeString(req.method()),
                            url: url,
                            headers: lines,
                            body: bodyStr && bodyStr.length > 4000 ? bodyStr.slice(0, 4000) + '...' : bodyStr
                        });
                    }
                }
            } catch (e) {
                emit('hook-miss', 'build: ' + e);
            }
            return req;
        };
        emit('hooked', builderName + '.build 完整转储');
    } catch (e) {
        emit('hook-miss', 'build: ' + e);
    }

    // 2.2 addHeader：抓 authorization 身份，以及签名类头部
    try {
        RB.addHeader.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
            try {
                var key = safeString(k);
                var val = safeString(v);
                if (key && val) {
                    var lk = key.toLowerCase();
                    if (lk === 'authorization') {
                        var info = describeJwt(val.replace(/^Bearer\s+/i, ''));
                        if (info && once('auth', JSON.stringify(info))) emit('AUTH-HEADER', info);
                    } else if (lk.indexOf('sign') >= 0 || lk.indexOf('app-id') >= 0 ||
                        lk === 'x-timestamp' || lk.indexOf('nonce') >= 0 ||
                        lk.indexOf('tsp') >= 0) {
                        var line = key + ': ' + val;
                        if (once('hdr', line)) emit('SIGN-HEADER', line);
                    }
                }
            } catch (e) { }
            return this.addHeader(k, v);
        };
        emit('hooked', builderName + '.addHeader');
    } catch (e) {
        emit('hook-miss', 'addHeader: ' + e);
    }

    // 2.3 认证类 URL，用于定位令牌来源端点
    try {
        RB.url.overload('java.lang.String').implementation = function (u) {
            try {
                var s = safeString(u);
                if (s && /oauth|auth|login|token|sms|tspCode|code/i.test(s)) {
                    if (once('url', s)) emit('AUTH-URL', s);
                }
            } catch (e) { }
            return this.url(u);
        };
    } catch (e) { }

    return true;
}

/* ---------- 2b. HTTP 兜底层：不依赖 okhttp 类名 ---------- */

// 头部判读：authorization 解 JWT；签名类头部原样输出
function noteHeader(k, v) {
    var key = safeString(k), val = safeString(v);
    if (!key || !val) return;
    var lk = key.toLowerCase();
    if (lk === 'authorization') {
        var info = describeJwt(val.replace(/^Bearer\s+/i, ''));
        if (info && once('auth', JSON.stringify(info))) emit('AUTH-HEADER', info);
        else if (once('authraw', val.slice(0, 48))) emit('SIGN-HEADER', key + ': ' + val.slice(0, 80) + '...');
    } else if (lk.indexOf('sign') >= 0 || lk.indexOf('app-id') >= 0 || lk === 'x-timestamp' ||
        lk.indexOf('nonce') >= 0 || lk.indexOf('tsp') >= 0 || lk.indexOf('tenant') >= 0 ||
        lk.indexOf('app-version') >= 0 || lk.indexOf('device') >= 0) {
        var line = key + ': ' + val;
        if (once('hdr2', line)) emit('SIGN-HEADER', line);
    }
}

var javaNetHooked = false;

function hookHttpLayer() {
    if (javaNetHooked) return;
    javaNetHooked = true;

    // (a) 通用基类：任何走 java.net 的 HTTP 客户端设头都会经过这里
    try {
        var UC = Java.use('java.net.URLConnection');
        try {
            UC.setRequestProperty.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
                try { noteHeader(k, v); } catch (e) { }
                return this.setRequestProperty(k, v);
            };
            emit('hooked', 'URLConnection.setRequestProperty');
        } catch (e) { emit('hook-miss', 'setRequestProperty: ' + e); }
        try {
            UC.addRequestProperty.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
                try { noteHeader(k, v); } catch (e) { }
                return this.addRequestProperty(k, v);
            };
            emit('hooked', 'URLConnection.addRequestProperty');
        } catch (e) { }
    } catch (e) {
        emit('hook-miss', 'URLConnection: ' + e);
    }

    // (b) Android 平台自带的 HttpURLConnection 就是重打包过的 okhttp，
    //     包名 com.android.okhttp.*，与第三方 okhttp3 无关 —— 按类名直接钩
    var platformImpls = [
        'com.android.okhttp.internal.huc.HttpURLConnectionImpl',
        'com.android.okhttp.internal.huc.HttpsURLConnectionImpl',
        'com.android.okhttp.internal.huc.JavaApiConverter',
        'com.android.okhttp.Request$Builder',
        'com.android.okhttp.Call'
    ];
    for (var i = 0; i < platformImpls.length; i++) {
        var pn = platformImpls[i];
        try {
            var PC = Java.use(pn);
            emit('hooked', 'platform-okhttp: ' + pn);
            try {
                PC.setRequestProperty.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
                    try { noteHeader(k, v); } catch (e) { }
                    return this.setRequestProperty(k, v);
                };
            } catch (e) { }
            try {
                PC.addRequestProperty.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
                    try { noteHeader(k, v); } catch (e) { }
                    return this.addRequestProperty(k, v);
                };
            } catch (e) { }
        } catch (e) { }
    }

    // (c) URL 构造：定位请求目标与令牌来源端点
    try {
        var URL = Java.use('java.net.URL');
        URL.$init.overload('java.lang.String').implementation = function (u) {
            try {
                var s = safeString(u);
                if (s && /zeekr|geely|gric|snc-|oauth|auth|login|token|sms|remoteControl/i.test(s)) {
                    if (once('url2', s)) emit('AUTH-URL', s);
                }
            } catch (e) { }
            return this.$init(u);
        };
        emit('hooked', 'java.net.URL.$init');
    } catch (e) { }
}

function noteUrl(u) {
    var s = safeString(u);
    if (!s) return;
    if (!/zeekr|geely|gric|snc-|oauth|auth|login|token|sms|remoteControl|control/i.test(s)) return;
    if (once('url3', s)) emit('AUTH-URL', s);
}

function dumpRequest(req) {
    try {
        var url = safeString(req.url().toString());
        noteUrl(url);
        var h = req.headers();
        var n = h.size();
        var lines = [];
        for (var i = 0; i < n; i++) {
            var hn = safeString(h.name(i));
            var hv = safeString(h.value(i));
            lines.push(hn + ': ' + hv);
            try { noteHeader(hn, hv); } catch (e) { }
        }
        var method = safeString(req.method());
        var key = method + '|' + url + '|' + lines.join(';');
        if (once('fullreq', key)) {
            emit('FULL-REQUEST', { method: method, url: url, headers: lines });
        }
    } catch (e) {
        emit('hook-miss', 'dumpRequest: ' + e);
    }
}

/* ---------- 2c. okhttp3 本体（App 实际网络栈） ---------- */

var okhttpHBdone = false;
var okhttpRBdone = false;
var okhttpBodydone = false;

function hookOkhttpClasses() {

    // Headers$Builder.add/set：所有请求头（含 x-signature / authorization）的唯一汇聚点
    if (!okhttpHBdone) try {
        var HB = Java.use('okhttp3.Headers$Builder');
        try {
            HB.add.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
                try { noteHeader(k, v); } catch (e) { }
                return this.add(k, v);
            };
            emit('hooked', 'okhttp3.Headers$Builder.add');
        } catch (e) { emit('hook-miss', 'HB.add: ' + e); }
        try {
            HB.set.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
                try { noteHeader(k, v); } catch (e) { }
                return this.set(k, v);
            };
            emit('hooked', 'okhttp3.Headers$Builder.set');
        } catch (e) { }
        okhttpHBdone = true;
    } catch (e) { }

    // Request$Builder：等它加载出来再装
    if (!okhttpRBdone) try {
        var RB = Java.use('okhttp3.Request$Builder');
        try {
            RB.build.implementation = function () {
                var req = this.build();
                try { dumpRequest(req); } catch (e) { }
                return req;
            };
            emit('hooked', 'okhttp3.Request$Builder.build');
        } catch (e) { emit('hook-miss', 'okhttp3 build: ' + e); }
        try {
            RB.addHeader.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
                try { noteHeader(k, v); } catch (e) { }
                return this.addHeader(k, v);
            };
        } catch (e) { }
        try {
            RB.url.overload('java.lang.String').implementation = function (u) {
                try { noteUrl(u); } catch (e) { }
                return this.url(u);
            };
            emit('hooked', 'okhttp3.Request$Builder.url');
        } catch (e) { }
        okhttpRBdone = true;
    } catch (e) { }

    // RequestBody.create：请求体明文（车控指令就在这里）
    if (!okhttpBodydone) try {
        var RBody = Java.use('okhttp3.RequestBody');
        var ovs = RBody.create.overloads;
        for (var i = 0; i < ovs.length; i++) {
            (function (ov) {
                try {
                    ov.implementation = function () {
                        try {
                            for (var k = 0; k < arguments.length; k++) {
                                var a = arguments[k];
                                var s = null;
                                try {
                                    var cn = a.getClass().getName();
                                    s = (cn === '[B') ? ('bytes[' + a.length + ']:' + bytesToHex(a).slice(0, 400))
                                        : safeString(a);
                                } catch (e) { s = safeString(a); }
                                if (s && s.length > 4 &&
                                    /zeekrlife|geely|gric|serviceParameters|command|AC\.temp|serviceId|VIN/i.test(s)) {
                                    if (once('rbody', s.slice(0, 200))) emit('REQUEST-BODY', s.slice(0, 2000));
                                }
                            }
                        } catch (e) { }
                        return ov.apply(this, arguments);
                    };
                } catch (e) { }
            })(ovs[i]);
        }
        emit('hooked', 'okhttp3.RequestBody.create');
        okhttpBodydone = true;
    } catch (e) { }
}

/* ---------- 2d. 原生 TLS 明文捕获（与网络栈无关的兜底） ---------- */

// 不论 App 用 okhttp3 / 平台 okhttp / Cronet / WebView / 原生 libcurl，
// HTTPS 请求在加密前必然经过 SSL_write(ssl, buf, num) —— 那一刻 buf 就是明文 HTTP 报文，
// 头里带着 x-signature，体里带着车控指令。这是唯一不依赖任何类名、也不怕混淆的抓法。
var sslHosts = {};      // SSL* 指针 -> SNI 主机名
var SSL_LIB_RE = /libssl|libcronet|libmonochrome|libconscrypt|boringssl|libttboringssl|libnative-lib|libzeekr/i;
var sslHooked = false;

function readCStr(p) {
    try {
        return (p.isNull() ? null : p.readUtf8String());
    } catch (e) {
        return null;
    }
}

function hookSslWrite() {
    if (sslHooked) return;
    sslHooked = true;

    var mods;
    try {
        mods = Process.enumerateModules();
    } catch (e) {
        return;
    }

    // 先装 SNI 记录：SSL_set_tlsext_host_name(ssl, "host") —— 用来识别这条连接发往谁
    var sniBound = 0;
    for (var i = 0; i < mods.length; i++) {
        var m = mods[i];
        if (!SSL_LIB_RE.test(m.name)) continue;
        var exps;
        try {
            exps = m.enumerateExports();
        } catch (e) {
            continue;
        }
        for (var j = 0; j < exps.length; j++) {
            var e = exps[j];
            if (e.type !== 'function') continue;
            if (e.name === 'SSL_set_tlsext_host_name') {
                (function (addr, mod) {
                    try {
                        Interceptor.attach(addr, {
                            onEnter: function (args) {
                                try {
                                    var host = readCStr(args[1]);
                                    if (host) {
                                        sslHosts[args[0].toString()] = host;
                                        if (/geely|zeekr|gric|snc-|jpc|amap|aliyun/i.test(host) &&
                                            once('sni', host)) {
                                            emit('TLS-SNI', { host: host, mod: mod });
                                        }
                                    }
                                } catch (err) { }
                            }
                        });
                        sniBound++;
                    } catch (err) { }
                })(e.address, m.name);
            }
        }
    }
    if (sniBound) emit('hooked', 'SSL_set_tlsext_host_name x' + sniBound);

    // 再装 SSL_write：拿明文
    var bound = 0;
    for (var k = 0; k < mods.length; k++) {
        var mm = mods[k];
        if (!SSL_LIB_RE.test(mm.name)) continue;
        var ex2;
        try {
            ex2 = mm.enumerateExports();
        } catch (e) {
            continue;
        }
        for (var n = 0; n < ex2.length; n++) {
            var f = ex2[n];
            if (f.type !== 'function') continue;
            if (f.name !== 'SSL_write' && f.name !== 'SSL_write_ex') continue;
            (function (addr, fname, mod) {
                try {
                    Interceptor.attach(addr, {
                        onEnter: function (args) {
                            try {
                                var ssl = args[0].toString();
                                var host = sslHosts[ssl] || null;
                                var buf, len;
                                if (fname === 'SSL_write') {
                                    buf = args[1];
                                    len = pint(args[2]);
                                } else {
                                    buf = args[1];
                                    len = 0;
                                    try { len = args[2].readU32(); } catch (e) { }
                                }
                                if (!buf || buf.isNull() || !(len > 0)) return;
                                var cap = len > 16384 ? 16384 : len;
                                var bytes = buf.readByteArray(cap);
                                var text = '';
                                try {
                                    text = String.fromCharCode.apply(null, new Uint8Array(bytes));
                                } catch (e) {
                                    var u8 = new Uint8Array(bytes);
                                    for (var q = 0; q < u8.length; q++) text += String.fromCharCode(u8[q]);
                                }
                                // 只留 HTTP 报文，且只留与本项目相关的域名，其余丢弃避免刷屏
                                if (text.indexOf('HTTP/') !== 0 && text.indexOf('POST ') !== 0 &&
                                    text.indexOf('GET ') !== 0) return;
                                var relevant = /geely|zeekr|gric|snc-|tsp|remoteControl|x-signature/i.test(text) ||
                                    (host && /geely|zeekr|gric|snc-/i.test(host));
                                if (!relevant) return;
                                var sigLine = '';
                                var sm = /x-signature:\s*(\S+)/i.exec(text);
                                if (sm) sigLine = sm[1];
                                if (!once('sslw', host + '|' + sigLine + '|' + text.slice(0, 120))) return;
                                emit('TLS-PLAINTEXT', {
                                    mod: mod,
                                    host: host,
                                    sig: sigLine,
                                    len: len,
                                    text: text.slice(0, 6000)
                                });
                            } catch (err) {
                                emit('hook-miss', 'SSL_write: ' + err);
                            }
                        }
                    });
                    bound++;
                } catch (err) { }
            })(f.address, f.name, mm.name);
        }
    }
    emit('hooked', 'SSL_write x' + bound);
}

/* ---------- 2e. 反反调试：抢在 App 检测之前把门关上 ---------- */

// App 多半在 native 层用 ptrace(PTRACE_TRACEME) 自附着来阻止别人调试。
// 我们在 spawn 阶段就先挂上钩子：把 PTRACE_TRACEME 直接吞掉返回 0，
// 让 App 以为「没人跟踪我」，同时保证 frida 自己的 attach 仍然有效。
function hookAntiDebugNative() {
    var ptrace_f, prctl_f;
    try {
        ptrace_f = Module.getExportByName(null, 'ptrace');
    } catch (e) { }

    if (ptrace_f) {
        try {
            Interceptor.attach(ptrace_f, {
                onEnter: function (args) {
                    this.req = pint(args[0]);
                },
                onLeave: function (retval) {
                    // PTRACE_TRACEME = 0：自附着。直接返回 0，骗过自检
                    if (this.req === 0) {
                        retval.replace(ptr('0'));
                    }
                }
            });
            emit('hooked', 'native ptrace (PTRACE_TRACEME 已吞)');
        } catch (e) {
            emit('hook-miss', 'ptrace: ' + e);
        }
    }

    try {
        prctl_f = Module.getExportByName(null, 'prctl');
    } catch (e) { }

    if (prctl_f) {
        try {
            Interceptor.attach(prctl_f, {
                onEnter: function (args) {
                    this.op = pint(args[0]);
                },
                onLeave: function (retval) {
                    // PR_SET_DUMPABLE=4：App 常把它设 0 让自己不可被 ptrace/gcore
                    if (this.op === 4) {
                        retval.replace(ptr('0'));
                    }
                }
            });
            emit('hooked', 'native prctl (PR_SET_DUMPABLE 已吞)');
        } catch (e) {
            emit('hook-miss', 'prctl: ' + e);
        }
    }
}

// Java 层的调试自检：一律回答「没有调试器」；同时把 Java 侧的自杀入口也记下来
function hookAntiDebugJava() {
    try {
        var D = Java.use('android.os.Debug');
        try {
            D.isDebuggerConnected.implementation = function () { return false; };
            emit('hooked', 'Debug.isDebuggerConnected -> false');
        } catch (e) { }
        try {
            D.waitingForDebugger.implementation = function () { return false; };
            emit('hooked', 'Debug.waitingForDebugger -> false');
        } catch (e) { }
        try {
            D.waitForDebugger.implementation = function () { return; };
            emit('hooked', 'Debug.waitForDebugger -> no-op');
        } catch (e) { }
    } catch (e) { }

    // Java 侧的自杀/冻结：无论谁调的，都留下调用栈
    try {
        var Proc = Java.use('android.os.Process');
        try {
            Proc.sendSignal.implementation = function (pid, sig) {
                var stack = '';
                try { stack = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()); } catch (e) { }
                if (once('jsig', pid + '|' + sig)) {
                    emit('SELF-KILL', { kind: 'Process.sendSignal', detail: 'pid=' + pid + ' sig=' + sig, bt: String(stack).slice(0, 1500) });
                }
                if (sig === 19 || sig === 20) {
                    if (once('jsigblock', String(sig))) emit('STOP-BLOCKED', 'Process.sendSignal sig=' + sig + ' -> 已拦截');
                    return this.sendSignal(pid, 0);
                }
                return this.sendSignal(pid, sig);
            };
        } catch (e) { }
        try {
            Proc.killProcess.implementation = function (pid) {
                var stack = '';
                try { stack = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()); } catch (e) { }
                if (once('jkill', 'killProcess' + pid)) {
                    emit('SELF-KILL', { kind: 'Process.killProcess', detail: 'pid=' + pid, bt: String(stack).slice(0, 1200) });
                }
                return this.killProcess(pid);
            };
        } catch (e) { }
        try {
            Proc.killProcessQuiet.implementation = function (pid) {
                if (once('jkill', 'killQuiet' + pid)) {
                    emit('SELF-KILL', { kind: 'Process.killProcessQuiet', detail: 'pid=' + pid });
                }
                return this.killProcessQuiet(pid);
            };
        } catch (e) { }
    } catch (e) { }

    try {
        var Sys = Java.use('java.lang.System');
        try {
            Sys.exit.implementation = function (code) {
                var stack = '';
                try { stack = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()); } catch (e) { }
                if (once('jexit', String(code))) {
                    emit('SELF-KILL', { kind: 'System.exit', detail: 'code=' + code, bt: String(stack).slice(0, 1200) });
                }
                return this.exit(code);
            };
        } catch (e) { }
    } catch (e) { }
}

/* ---------- 2f. 反调试取证：它到底靠什么发现我们 ---------- */

// 思路：不猜、不堵，先取证。
//   ① 记录 App 读过的每一个 /proc/* 敏感路径（maps / task / status / mem / tcp ...）
//   ② 把这些文件的内容抓下来，看它在找什么关键字
//   ③ 拦截所有「自杀类」调用（exit/abort/kill/tgkill/raise）并打调用栈
//      —— 谁把它杀了，一跑就知道。
var procFds = {};        // fd -> 被监控的 /proc 路径
var procSeenPath = {};
var procHit = 0;

var SENSITIVE_PROC_RE = /\/proc\/(self|thread-self|\d+)\/(maps|smaps|task|status|stat|statm|cmdline|mem|mountinfo|fd|cgroup|net\/tcp|net\/tcp6|net\/unix|attr)/;

function noteProcPath(path) {
    if (!path || path.indexOf('/proc') !== 0) return null;
    if (!SENSITIVE_PROC_RE.test(path)) return null;
    if (once('procopen', path)) emit('PROC-OPEN', path);
    return path;
}

function backtraceHere(ctx) {
    var out = [];
    try {
        var frames = Thread.backtrace(ctx, Backtracer.ACCURATE);
        for (var i = 0; i < frames.length && i < 8; i++) {
            var sym = DebugSymbol.fromAddress(frames[i]);
            out.push(sym.toString());
        }
    } catch (e) {
        out.push('<bt-err:' + e + '>');
    }
    return out;
}

function hookProcScanDiag() {
    var libc;
    try {
        libc = Process.getModuleByName('libc.so');
    } catch (e) {
        emit('hook-miss', 'libc.so 找不到: ' + e);
        return;
    }

    function tryHook(name, onEnter) {
        var addr = null;
        try {
            addr = libc.findExportByName(name);
        } catch (e) { }
        if (!addr) return false;
        try {
            Interceptor.attach(addr, { onEnter: onEnter });
            return true;
        } catch (e) {
            return false;
        }
    }

    var n = 0;

    // ---- 1) 打开类：抓路径 + 记录 fd ----
    try {
        var oa = libc.findExportByName('openat');
        if (oa) {
            Interceptor.attach(oa, {
                onEnter: function (args) {
                    try {
                        var p = args[1].readUtf8String();
                        var hit = noteProcPath(p);
                        if (hit) this.hitPath = hit;
                    } catch (e) { }
                },
                onLeave: function (retval) {
                    try {
                        if (this.hitPath) {
                            var fd = pint(retval);
                            if (fd >= 0) procFds[fd] = this.hitPath;
                        }
                    } catch (e) { }
                }
            });
        }
    } catch (e) { }

    ['open', 'open64'].forEach(function (fn) {
        try {
            var a = libc.findExportByName(fn);
            if (!a) return;
            Interceptor.attach(a, {
                onEnter: function (args) {
                    try {
                        var p = args[0].readUtf8String();
                        var hit = noteProcPath(p);
                        if (hit) this.hitPath = hit;
                    } catch (e) { }
                },
                onLeave: function (retval) {
                    try {
                        if (this.hitPath) {
                            var fd = pint(retval);
                            if (fd >= 0) procFds[fd] = this.hitPath;
                        }
                    } catch (e) { }
                }
            });
        } catch (e) { }
    });

    // 只看不打开：access / stat 系列也常被用来探测
    ['access', 'faccessat', 'stat', 'stat64', 'lstat'].forEach(function (fn) {
        try {
            var a = libc.findExportByName(fn);
            if (!a) return;
            Interceptor.attach(a, {
                onEnter: function (args) {
                    try {
                        var idx = (fn === 'faccessat') ? 1 : 0;
                        noteProcPath(args[idx].readUtf8String());
                    } catch (e) { }
                }
            });
        } catch (e) { }
    });

    // ---- 2) read：对监控中的 fd，看它读到了什么、在找什么 ----
    function onReadEnter(args, which) {
        this.fd = pint(args[0]);
        this.buf = args[1];
        this.cnt = pint(args[2]);
        this.which = which;
    }
    function onReadLeave(retval) {
        try {
            var fd = this.fd;
            var path = procFds[fd];
            if (!path) return;
            var ret = pint(retval);
            if (!(ret > 0)) return;
            if (procHit > 400) return;
            procHit++;
            var cap = ret > 8192 ? 8192 : ret;
            var bytes = this.buf.readByteArray(cap);
            var u8 = new Uint8Array(bytes);
            var txt = '';
            for (var i = 0; i < u8.length; i++) txt += String.fromCharCode(u8[i]);
            // 判定是否含「反调试关键字」
            var marks = ['frida', 'Frida', 'FRIDA', 'gum-js-loop', 'gmain', 'pool-frida',
                'gadget', 'linjector', 'gum-gc', 'TracerPid', 'gdb', 'xposed', 'substrate'];
            var found = [];
            for (var m = 0; m < marks.length; m++) {
                if (txt.indexOf(marks[m]) >= 0) found.push(marks[m]);
            }
            var head = txt.replace(/\s+/g, ' ').slice(0, 300);
            var key = path + '|' + found.join(',') + '|' + head.slice(0, 120);
            if (once('procread', key)) {
                emit('PROC-READ', {
                    path: path, len: ret,
                    marks: found,
                    head: head
                });
            }
        } catch (e) { }
    }

    ['read', 'pread', 'pread64'].forEach(function (fn) {
        try {
            var a = libc.findExportByName(fn);
            if (!a) return;
            Interceptor.attach(a, {
                onEnter: function (args) { onReadEnter.call(this, args, fn); },
                onLeave: onReadLeave
            });
            n++;
        } catch (e) { }
    });

    // ---- 3) 自杀类调用：谁杀了进程 ----
    function reportKill(kind, detail, ctx) {
        if (!once('kill', kind + '|' + detail)) return;
        emit('SELF-KILL', { kind: kind, detail: detail, bt: backtraceHere(ctx) });
    }

    ['exit', '_exit', '_Exit', 'abort'].forEach(function (fn) {
        try {
            var a = libc.findExportByName(fn);
            if (!a) return;
            Interceptor.attach(a, {
                onEnter: function (args) {
                    var code = '?';
                    try { code = args[0].toString(); } catch (e) { }
                    reportKill('libc.' + fn, 'code=' + code, this.context);
                }
            });
            n++;
        } catch (e) { }
    });

    // ---- 3b) 阻断「向自己发 SIGSTOP」——加固壳靠它冻结线程做反调试检查，----
    //          检查不过就不唤醒；我们让这个信号发不出去（sig 改成 0），
    //          只改参数、不跳过调用，其它信号完全不受影响。
    var STOP_SIGS = { 19: 'SIGSTOP', 20: 'SIGTSTP' };

    function sigIndexOf(fn) {
        if (fn === 'kill') return 1;
        if (fn === 'tgkill') return 2;
        if (fn === 'tkill') return 1;
        if (fn === 'pthread_kill') return 1;
        return 0;   // raise(sig)
    }

    ['kill', 'tgkill', 'tkill', 'raise', 'pthread_kill'].forEach(function (fn) {
        try {
            var a = libc.findExportByName(fn);
            if (!a) return;
            Interceptor.attach(a, {
                onEnter: function (args) {
                    var d = '';
                    try {
                        if (fn === 'kill') d = 'pid=' + args[0] + ' sig=' + args[1];
                        else if (fn === 'tgkill') d = 'tgid=' + args[0] + ' tid=' + args[1] + ' sig=' + args[2];
                        else if (fn === 'tkill') d = 'tid=' + args[0] + ' sig=' + args[1];
                        else if (fn === 'pthread_kill') d = 'thread=' + args[0] + ' sig=' + args[1];
                        else d = 'sig=' + args[0];
                    } catch (e) { }
                    reportKill('libc.' + fn, d, this.context);

                    try {
                        var si = sigIndexOf(fn);
                        var sig = pint(args[si]);
                        if (STOP_SIGS[sig]) {
                            args[si] = ptr(0);      // 改成 0 号信号 = 什么都不发
                            if (once('stopblock', fn + sig)) {
                                emit('STOP-BLOCKED', fn + ' ' + STOP_SIGS[sig] + ' -> 已拦截');
                            }
                        }
                    } catch (e) { }
                }
            });
            n++;
        } catch (e) { }
    });

    // 直发 syscall 的情况：kill=129 / tkill=130 / tgkill=131
    try {
        var sa = libc.findExportByName('syscall');
        if (sa) {
            Interceptor.attach(sa, {
                onEnter: function (args) {
                    try {
                        var nr = pint(args[0]);
                        if (nr === 129 || nr === 131 || nr === 94 || nr === 62) {   // kill/tgkill/exit_group/?
                            var d = 'syscall nr=' + nr + ' a1=' + args[1] + ' a2=' + args[2] + ' a3=' + args[3];
                            reportKill('syscall', d, this.context);
                        }
                        // sig 在 syscall 的第几个参数
                        var si = (nr === 129 || nr === 130) ? 2 : (nr === 131 ? 3 : -1);
                        if (si > 0) {
                            var sig = pint(args[si]);
                            if (STOP_SIGS[sig]) {
                                args[si] = ptr(0);
                                if (once('stopblock', 'syscall' + nr)) {
                                    emit('STOP-BLOCKED', 'syscall nr=' + nr + ' ' + STOP_SIGS[sig] + ' -> 已拦截');
                                }
                            }
                        }
                    } catch (e) { }
                }
            });
            n++;
        }
    } catch (e) { }

    emit('hooked', 'proc-scan 诊断钩子 x' + n + '（PROC-OPEN / PROC-READ / SELF-KILL）');
}

/* ---------- 2g. maps 洗白：让 libkadp 看不到 frida ---------- */

// 本 App 的 libkadp.so 会读 /proc/self/maps 找 frida 的痕迹：
//     /memfd:frida-agent-64.so (deleted)
// 找到就故意 SIGSEGV 自杀（伪装成普通崩溃）。
//
// 做法：在 openat/open 这一层把路径重定向到我们自己生成的「洗白版 maps」。
// 比在 read 层逐块擦除可靠 —— 不存在关键字跨块漏网的问题。
//
// 洗白规则：凡命中关键字（frida/gum/gadget/linjector 等）的行，整行替换成等长空格。
var MAPS_FAKE_PATH = '/data/user/0/' + PKG + '/cache/.zk_maps';
var MAPS_MARK_RE = /frida|frida-agent|gum-js|gum-ash|linjector|gadget|\bzsvc\b|frida-server|re\.frida/i;
var mapsFake = { at: 0, path: null, count: 0 };

function rawSyscallFn() {
    var p = Module.getExportByName(null, 'syscall');
    return new NativeFunction(p, 'long', ['long', 'long', 'long', 'long', 'long', 'long']);
}

// 用原始 syscall 读真实 maps —— 刻意绕开被钩的 libc，避免递归
function readRealMaps() {
    var sys = rawSyscallFn();
    var p = Memory.allocUtf8String('/proc/self/maps');
    var fd = sys(56, -100, p, 0, 0, 0);          // openat(AT_FDCWD, path, O_RDONLY)
    if (fd < 0) return null;
    var buf = Memory.alloc(1 << 16);
    var parts = [];
    for (var i = 0; i < 64; i++) {
        var n = sys(63, fd, buf, 1 << 16, 0, 0);  // read
        if (n <= 0) break;
        parts.push(new Uint8Array(buf.readByteArray(n)));
        if (n < (1 << 16)) break;
    }
    sys(57, fd, 0, 0, 0, 0);                     // close
    var total = 0;
    for (var j = 0; j < parts.length; j++) total += parts[j].length;
    var all = new Uint8Array(total);
    var off = 0;
    for (var k = 0; k < parts.length; k++) { all.set(parts[k], off); off += parts[k].length; }
    var txt = '';
    for (var m = 0; m < all.length; m++) txt += String.fromCharCode(all[m]);
    return txt;
}

function sanitizeMapsText(txt) {
    var lines = txt.split('\n');
    var hidden = 0;
    for (var i = 0; i < lines.length; i++) {
        if (MAPS_MARK_RE.test(lines[i])) {
            var blanks = '';
            for (var c = 0; c < lines[i].length; c++) blanks += ' ';
            lines[i] = blanks;
            hidden++;
        }
    }
    return { text: lines.join('\n'), hidden: hidden };
}

function writeFakeMaps() {
    var real = readRealMaps();
    if (!real) return null;
    var res = sanitizeMapsText(real);
    var bytes = [];
    for (var i = 0; i < res.text.length; i++) bytes.push(res.text.charCodeAt(i) & 0xff);
    var sys = rawSyscallFn();
    var p = Memory.allocUtf8String(MAPS_FAKE_PATH);
    var fd = sys(56, -100, p, 577, 384, 0);      // O_WRONLY|O_CREAT|O_TRUNC, 0600
    if (fd < 0) return null;
    var data = Memory.alloc(bytes.length ? bytes.length : 1);
    data.writeByteArray(bytes);
    var written = 0;
    while (written < bytes.length) {
        var n = sys(64, fd, data.add(written), bytes.length - written, 0, 0);   // write
        if (n <= 0) break;
        written += n;
    }
    sys(57, fd, 0, 0, 0, 0);
    mapsFake.at = Date.now();
    mapsFake.count = res.hidden;
    return MAPS_FAKE_PATH;
}

function fakeMapsPath() {
    // 2 秒内复用，避免频繁重写
    if (mapsFake.path && (Date.now() - mapsFake.at) < 2000) return mapsFake.path;
    var p = writeFakeMaps();
    if (!p) return null;
    if (!mapsFake.path) {
        mapsFake.path = p;
        emit('MAPS-SANITIZE', '已启用：/proc/self/maps -> ' + p);
    }
    return p;
}

var MAPS_PATH_RE = /^\/proc\/(self|thread-self|\d+)\/(task\/\d+\/)?maps$/;

function hookMapsSanitizer() {
    var libc;
    try {
        libc = Process.getModuleByName('libc.so');
    } catch (e) {
        return;
    }

    function redirect(path) {
        if (!path || !MAPS_PATH_RE.test(path)) return null;
        var fake = fakeMapsPath();
        if (!fake) return null;
        if (once('mapsredir', path)) emit('MAPS-REDIRECT', path + ' -> ' + fake);
        return fake;
    }

    function hookOpen(name, pathIdx, retFd) {
        try {
            var a = libc.findExportByName(name);
            if (!a) return;
            Interceptor.attach(a, {
                onEnter: function (args) {
                    try {
                        var p = args[pathIdx].readUtf8String();
                        var fake = redirect(p);
                        if (fake) this.fakePtr = Memory.allocUtf8String(fake);
                    } catch (e) { }
                    if (this.fakePtr) args[pathIdx] = this.fakePtr;
                }
            });
        } catch (e) { }
    }

    hookOpen('openat', 1, true);
    hookOpen('open', 0, true);
    hookOpen('open64', 0, true);
    hookOpen('fopen', 0, false);
    hookOpen('fopen64', 0, false);
    emit('hooked', 'maps 洗白（openat/open/fopen 路径重定向）');
}


function hookJavaClass(name) {
    if (!isAppClass(name)) return false;
    var C;
    try {
        C = Java.use(name);
    } catch (e) {
        return false;
    }
    if (!once('cls', name)) return true;
    emit('class-found', name);

    var methods;
    try {
        methods = C.class.getDeclaredMethods();
    } catch (e) {
        return true;
    }
    // 敏感类（名字里带 secret/sign/encrypt）的方法名多半被混淆成 a()/b()，
    // 这时按方法名过滤会一条都钩不到 —— 改成全钩（设上限防爆）。
    var hookAll = /secret|sign|encrypt|digest/i.test(name);
    var limit = hookAll ? 60 : 1e9;
    var hookedCount = 0;
    for (var i = 0; i < methods.length; i++) {
        if (hookedCount >= limit) break;
        var mname = methods[i].getName();
        if (!hookAll && !/secret|sign|key|token|hmac|digest|encrypt/i.test(mname)) continue;
        var overloads;
        try {
            overloads = C[mname].overloads;
        } catch (e) {
            continue;
        }
        for (var j = 0; j < overloads.length; j++) {
            if (hookedCount >= limit) break;
            hookedCount++;
            (function (cname, mname, ov) {
                try {
                    ov.implementation = function () {
                        var args = [];
                        for (var k = 0; k < arguments.length; k++) {
                            var raw = arguments[k];
                            var s = null;
                            try {
                                if (raw !== null && raw !== undefined) {
                                    var cn = raw.getClass().getName();
                                    if (cn === '[B') {
                                        s = 'bytes[' + raw.length + ']:' + bytesToHex(raw).slice(0, 300);
                                    } else {
                                        s = safeString(raw);
                                    }
                                }
                            } catch (e) { s = safeString(raw); }
                            if (s !== null && s.length < 1024) args.push(s);
                        }
                        var ret;
                        try {
                            ret = ov.apply(this, arguments);
                        } catch (err) {
                            emit('call-error', cname + '.' + mname + ' -> ' + err);
                            throw err;
                        }
                        var rs = null;
                        try {
                            if (ret !== null && ret !== undefined) {
                                var rcn = ret.getClass().getName();
                                rs = (rcn === '[B')
                                    ? ('bytes[' + ret.length + ']:' + bytesToHex(ret).slice(0, 300))
                                    : safeString(ret);
                            }
                        } catch (e) { rs = safeString(ret); }
                        var line = cname + '.' + mname + '(' + args.join(', ') + ') = ' + rs;
                        if (once('call', line)) emit('java-call', line);
                        if (looksLikeKey(rs)) emit('KEY-CANDIDATE', { from: cname + '.' + mname, value: rs });
                        for (var k2 = 0; k2 < args.length; k2++) {
                            if (looksLikeKey(args[k2])) {
                                emit('KEY-CANDIDATE', { from: cname + '.' + mname + ' arg' + k2, value: args[k2] });
                            }
                        }
                        return ret;
                    };
                } catch (e) { }
            })(name, mname, overloads[j]);
        }
    }
    return true;
}

function scanLoadedClasses() {
    var all;
    try {
        all = Java.enumerateLoadedClassesSync();
    } catch (e) {
        return [];
    }
    var pats = [
        /secret/i, /sign/i, /http/i, /encrypt/i, /cipher/i, /digest/i,
        /hmac/i, /token/i, /okhttp/i, /okio/i, /interceptor/i,
        /zeekr.*(net|api|http)/i, /haohan/i, /geely/i
    ];
    var hits = [];
    for (var i = 0; i < all.length; i++) {
        var n = all[i];
        if (!isAppClass(n)) continue;      // 排除 AOSP/框架，否则噪声上千条
        for (var j = 0; j < pats.length; j++) {
            if (pats[j].test(n)) { hits.push(n); break; }
        }
    }
    if (hits.length > 200) hits = hits.slice(0, 200);
    // 每轮都会重扫，只在命中集合变化时才输出，避免刷屏
    var hk = hits.join(',');
    if (hits.length && hk !== lastHitsKey) {
        lastHitsKey = hk;
        emit('class-hits', hits);
    }
    return hits;
}

/* ---------- 4. 原生层：带 SecretKey/Sign 的导出 ---------- */

function hookNative() {
    var mods, hits = [];
    try {
        mods = Process.enumerateModules();
    } catch (e) {
        return;
    }
    for (var i = 0; i < mods.length && hits.length < 40; i++) {
        var m = mods[i];
        var name = m.name.toLowerCase();
        var path = (m.path || '').toLowerCase();
        // 只钩 App 自带的库。libcrypto/libssl 是系统 TLS 库，钩了会干扰握手且全是噪声
        if (/^\/system\/|^\/apex\/|^\/system_ext\//.test(path)) continue;
        if (/^lib(crypto|ssl|javacrypto|boringssl|conscrypt)/.test(name)) continue;
        if (!/zeekr|geely|haohan|encryptor|conch|native-lib|applib|seclib|env|sign/i.test(name)) continue;
        var exps;
        try {
            exps = m.enumerateExports();
        } catch (e) {
            continue;
        }
        for (var j = 0; j < exps.length && hits.length < 40; j++) {
            var e = exps[j];
            if (e.type !== 'function') continue;
            if (!/secretkey|signkey|getsecret|setsig|signature|hmac|calc.*sign|get.*sign/i.test(e.name)) continue;
            var full = m.name + '!' + e.name;
            hits.push(full);
            (function (fullName, addr) {
                try {
                    Interceptor.attach(addr, {
                        onLeave: function (retval) {
                            var s = null;
                            try { s = safeString(retval); } catch (e) { }
                            if (once('nat', fullName + s)) {
                                emit('native-ret', { fn: fullName, retval: s });
                            }
                        }
                    });
                } catch (err) {
                    emit('hook-miss', fullName + ': ' + err);
                }
            })(full, e.address);
        }
    }
    emit('native-hits', hits);
}

/* ---------- 启动 ---------- */

// 关键顺序：原生钩子先装（不等 Java），然后才是 Java 层。
// 用 --spawn 注入时脚本在 App 主逻辑之前加载，这一段就是「抢跑窗口」。
//
// 注意本 App 有 libkadp.so 反调试：它做完整性校验，发现代码被打了钩子就直接
// SIGSEGV 自杀。所以钩子越少越安全 —— minimal 模式只装 SSL_write 一个，
// 这是唯一「原生、单点、不改 Java 方法表」的抓法，但要抓的明文一样能拿到。
var MODE = (typeof ZKR_MODE === 'undefined') ? 'full' : ZKR_MODE;

if (MODE === 'minimal') {
    hookSslWrite();
    emit('start', 'minimal 模式：只装 SSL_write 明文捕获 (frida ' + Frida.version + ')');
} else if (MODE === 'sanitize') {
    hookMapsSanitizer();
    hookSslWrite();
    emit('start', 'sanitize 模式：maps 洗白 + SSL_write 明文捕获 (frida ' + Frida.version + ')');
} else {
    hookAntiDebugNative();
    hookProcScanDiag();
    hookMapsSanitizer();
    hookSslWrite();

    if (typeof Java === 'undefined' || Java === null) {
        send({
            kind: 'fatal',
            data: 'Java 桥未加载。请通过 tools/zeekr_frida.py 运行（它会自动把 frida-tools 自带的 java.js 桥拼进来）。'
        });
    } else {
        Java.perform(function () {
            emit('start', 'frida hook 已加载 (frida ' + Frida.version + ')');
            hookAntiDebugJava();

            var known = [
                'com.haohan.module.http.encrypt.HttpSecretKey',
                'com.haohan.module.http.encrypt.HttpSecretKeyHelper',
            ];
            for (var i = 0; i < known.length; i++) hookJavaClass(known[i]);

            hookCrypto();

            // 类是按需加载的，网络栈往往要等第一次请求（甚至打开车控页）才出现。
            // 所以扫描不能停：改成全程持续，间隔 3 秒，一旦抓够就自然停下。
            var rounds = 0;
            var okHttpDone = false;

            function pass() {
                try {
                    if (!okHttpDone) okHttpDone = hookOkHttp();
                } catch (e) {
                    emit('hook-miss', 'hookOkHttp: ' + e);
                }
                try {
                    hookOkhttpClasses();
                } catch (e) {
                    emit('hook-miss', 'hookOkhttpClasses: ' + e);
                }
                try {
                    hookHttpLayer();
                } catch (e) {
                    emit('hook-miss', 'hookHttpLayer: ' + e);
                }
                var hits = scanLoadedClasses() || [];
                for (var j = 0; j < hits.length; j++) hookJavaClass(hits[j]);
                rounds++;
                if (rounds === 1) {
                    emit('ready', '钩子安装完成，进入持续扫描（每 3 秒一轮）');
                }
                if (emitCount < EMIT_CAP) {
                    setTimeout(function () {
                        Java.perform(pass);
                    }, 3000);
                }
            }

            Java.perform(pass);
            hookNative();
        });
    }
}
