#!/usr/bin/env node
/**
 * juanev 内容加密工具（方案 C）
 *
 * 用法：
 *   node tools/encrypt.js all                    加密 .plain-src 下全部 HTML 到仓库对应位置
 *   node tools/encrypt.js encrypt <file.html>    备份明文到 .plain-src 后原地加密（可多个文件）
 *   node tools/encrypt.js bundle <file> [--out 输出.html]
 *                                                把 md / 图片 / PDF / Office 等打包成加密页面
 *
 * 口令来源优先级：--pass <口令> > 环境变量 JUANEV_PASS > 用户目录 ~/.juanev-key.txt
 * 算法：PBKDF2-SHA256(600000) → AES-256-GCM，密文 = ciphertext || tag（Web Crypto 兼容格式）
 * 说明：全站共用一个固定 salt，因此一次派生出的密钥可解密所有页面，实现"输一次全站通用"。
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const PLAIN_DIR = path.join(ROOT, '.plain-src');
const ITER = 600000;
const SALT_B64 = 'Fv7HrMWTpUDb8E1Za/fFY4qv8Mrnj32grAnsX5he5X0=';
const KEY_FILE = path.join(process.env.USERPROFILE || process.env.HOME || '.', '.juanev-key.txt');

function fail(msg) {
  console.error('错误：' + msg);
  process.exit(1);
}

function getPassword(cliPass) {
  if (cliPass) return cliPass;
  if (process.env.JUANEV_PASS) return process.env.JUANEV_PASS;
  if (fs.existsSync(KEY_FILE)) {
    const v = fs.readFileSync(KEY_FILE, 'utf8').trim();
    if (v) return v;
  }
  fail('缺少口令：请用 --pass <口令>、设置 JUANEV_PASS，或创建 ' + KEY_FILE);
}

function parseArgs(argv) {
  const rest = [];
  let pass = null, out = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--pass') { pass = argv[++i]; continue; }
    if (argv[i] === '--out') { out = argv[++i]; continue; }
    rest.push(argv[i]);
  }
  return { rest: rest, pass: pass, out: out };
}

function encryptBuf(buf, password) {
  const key = crypto.pbkdf2Sync(Buffer.from(password, 'utf8'), Buffer.from(SALT_B64, 'base64'), ITER, 32, 'sha256');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(buf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    payload: Buffer.concat([enc, tag]).toString('base64'),
    iv: iv.toString('base64')
  };
}

function humanSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/* ============================ 页面壳 ============================ */

function buildShell(payload, iv, opt) {
  const tpl = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>受保护页面</title>
<style>
  html,body{margin:0;height:100%;background:#f1efe8;font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
  #sg{position:fixed;top:0;right:0;bottom:0;left:0;display:flex;align-items:center;justify-content:center;padding:20px;box-sizing:border-box;visibility:visible}
  .sg-card{background:#fff;border:1px solid rgba(0,0,0,.12);border-radius:12px;padding:28px 24px;width:340px;max-width:100%;box-sizing:border-box;box-shadow:0 8px 30px rgba(0,0,0,.06)}
  .sg-t{font-size:15px;font-weight:500;color:#2c2c2a;margin:0 0 6px;text-align:center}
  .sg-d{font-size:12px;color:#888780;margin:0 0 16px;text-align:center;word-break:break-all}
  .sg-i{width:100%;box-sizing:border-box;border:1px solid rgba(0,0,0,.28);border-radius:8px;padding:10px 12px;font-size:14px;outline:none}
  .sg-i:focus{border-color:#185fa5}
  .sg-err{border-color:#e24b4a!important}
  .sg-m{font-size:12px;color:#a32d2d;min-height:16px;margin:8px 0 0;text-align:center}
  .sg-b{width:100%;margin-top:12px;background:#185fa5;color:#fff;border:0;border-radius:8px;padding:11px 0;font-size:14px;cursor:pointer}
  .sg-b:active{background:#0c447c}
  .sg-b:disabled{opacity:.55;cursor:default}
  .sg-f{font-size:11px;color:#b4b2a9;margin:14px 0 0;text-align:center}
</style>
</head>
<body>
<div id="sg">
  <div class="sg-card">
    <p class="sg-t">请输入访问口令</p>
    <p class="sg-d" id="sgd"></p>
    <input class="sg-i" id="sgi" type="password" autocomplete="off" placeholder="口令">
    <p class="sg-m" id="sgm"></p>
    <button class="sg-b" id="sgb" type="button">解锁</button>
    <p class="sg-f">内容已加密存储，口令正确才能解密显示</p>
  </div>
</div>
<script>
(function () {
  var PAYLOAD = "${payload}";
  var SALT = "${SALT_B64}";
  var IV = "${iv}";
  var ITER = ${ITER};
  var MODE = "${opt.mode || 'html'}";
  var DL_NAME = ${JSON.stringify(opt.downloadName || '')};
  var DL_MIME = ${JSON.stringify(opt.downloadMime || 'application/octet-stream')};
  var NOTE = ${JSON.stringify(opt.note || '')};
  var LS = 'juanev_k1';

  var card = document.getElementById('sg');
  var input = document.getElementById('sgi');
  var msg = document.getElementById('sgm');
  var btn = document.getElementById('sgb');
  var desc = document.getElementById('sgd');
  if (NOTE) desc.textContent = NOTE; else desc.textContent = '';

  function fromB64(b64) {
    var bin = atob(b64), arr = new Uint8Array(bin.length), i;
    for (i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }
  function toB64(buf) {
    var bytes = new Uint8Array(buf), s = '', i;
    for (i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function loadKey() {
    try {
      var raw = localStorage.getItem(LS);
      if (!raw) return null;
      var v = JSON.parse(raw);
      if (!v || typeof v.exp !== 'number' || Date.now() > v.exp) return null;
      return v.k;
    } catch (e) { return null; }
  }
  function saveKey(rawB64) {
    try {
      localStorage.setItem(LS, JSON.stringify({ k: rawB64, exp: Date.now() + 30 * 864e5 }));
    } catch (e) {}
  }

  function derive(password) {
    var enc = new TextEncoder();
    return crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey'])
      .then(function (base) {
        return crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: fromB64(SALT), iterations: ITER, hash: 'SHA-256' },
          base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']
        );
      });
  }

  function decrypt(key) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(IV) }, key, fromB64(PAYLOAD));
  }

  function showError(text) {
    msg.textContent = text;
    input.classList.add('sg-err');
    input.focus();
    input.select();
    btn.disabled = false;
  }

  function render(buf) {
    if (MODE === 'download') {
      var blob = new Blob([buf], { type: DL_MIME });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url; a.download = DL_NAME;
      document.body.appendChild(a); a.click();
      setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
      card.innerHTML = '<div class="sg-card"><p class="sg-t">文件已解密</p>' +
        '<p class="sg-d">' + DL_NAME + '</p>' +
        '<p class="sg-m" style="color:#3b6d11">正在下载，如未自动开始请重新点开本页</p>' +
        '<button class="sg-b" id="again" type="button">再次下载</button></div>';
      var again = document.getElementById('again');
      if (again) again.addEventListener('click', function () {
        var b2 = new Blob([buf], { type: DL_MIME });
        var u2 = URL.createObjectURL(b2);
        var a2 = document.createElement('a');
        a2.href = u2; a2.download = DL_NAME;
        document.body.appendChild(a2); a2.click();
        setTimeout(function () { URL.revokeObjectURL(u2); }, 60000);
      });
      return;
    }
    var html = new TextDecoder('utf-8').decode(buf);
    document.open();
    document.write(html);
    document.close();
  }

  function tryCachedKey() {
    var k = loadKey();
    if (!k) return Promise.resolve(false);
    return crypto.subtle.importKey('raw', fromB64(k), { name: 'AES-GCM' }, true, ['decrypt'])
      .then(function (key) {
        return decrypt(key).then(function (buf) {
          render(buf);
          return true;
        }, function () { return false; });
      })
      .catch(function () { return false; });
  }

  function unlock() {
    var pw = input.value;
    if (!pw) { showError('请输入口令'); return; }
    input.classList.remove('sg-err');
    msg.textContent = '正在解密…';
    btn.disabled = true;
    derive(pw).then(function (key) {
      return decrypt(key).then(function (buf) {
        crypto.subtle.exportKey('raw', key).then(function (raw) { saveKey(toB64(raw)); }, function () {});
        render(buf);
      });
    }).catch(function () {
      msg.textContent = '口令不正确，请重试';
      input.classList.add('sg-err');
      input.focus();
      input.select();
      btn.disabled = false;
    });
  }

  btn.addEventListener('click', unlock);
  input.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') unlock(); });

  tryCachedKey().then(function (ok) {
    if (!ok) {
      msg.textContent = '';
      setTimeout(function () { try { input.focus(); } catch (e) {} }, 60);
    }
  });
})();
</script>
</body>
</html>
`;
  return tpl;
}

/* ========================= md → HTML ========================= */

function mdToHtml(src, titleText) {
  const lines = src.replace(/\r\n/g, '\n').split('\n');
  let i = 0;
  const out = [];
  const inline = (t) => {
    let s = escapeHtml(t);
    s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/(^|[^*])\*([^*]+)\*/g, '$1<em>$2</em>');
    s = s.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img alt="$1" src="$2">');
    s = s.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
    return s;
  };

  while (i < lines.length) {
    const line = lines[i];
    if (/^\s*$/.test(line)) { i++; continue; }

    if (/^```/.test(line)) {
      const lang = line.replace(/^```/, '').trim();
      const buf = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) buf.push(lines[i++]);
      i++;
      out.push('<pre' + (lang ? ' data-lang="' + escapeHtml(lang) + '"' : '') + '><code>' + escapeHtml(buf.join('\n')) + '</code></pre>');
      continue;
    }

    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) { out.push('<h' + h[1].length + '>' + inline(h[2]) + '</h' + h[1].length + '>'); i++; continue; }

    if (/^\s*(---|\*\*\*|___)\s*$/.test(line)) { out.push('<hr>'); i++; continue; }

    if (/^>\s?/.test(line)) {
      const buf = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) buf.push(lines[i++].replace(/^>\s?/, ''));
      out.push('<blockquote>' + inline(buf.join(' ')) + '</blockquote>');
      continue;
    }

    if (/^\s*[-*+]\s+/.test(line)) {
      const buf = [];
      while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) buf.push('<li>' + inline(lines[i++].replace(/^\s*[-*+]\s+/, '')) + '</li>');
      out.push('<ul>' + buf.join('') + '</ul>');
      continue;
    }

    if (/^\s*\d+[.)]\s+/.test(line)) {
      const buf = [];
      while (i < lines.length && /^\s*\d+[.)]\s+/.test(lines[i])) buf.push('<li>' + inline(lines[i++].replace(/^\s*\d+[.)]\s+/, '')) + '</li>');
      out.push('<ol>' + buf.join('') + '</ol>');
      continue;
    }

    if (/^\s*\|.*\|\s*$/.test(line) && i + 1 < lines.length && /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1])) {
      const head = line.trim().replace(/^\||\|$/g, '').split('|').map((c) => '<th>' + inline(c.trim()) + '</th>').join('');
      i += 2;
      const rows = [];
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) {
        rows.push('<tr>' + lines[i].trim().replace(/^\||\|$/g, '').split('|').map((c) => '<td>' + inline(c.trim()) + '</td>').join('') + '</tr>');
        i++;
      }
      out.push('<table><thead><tr>' + head + '</tr></thead><tbody>' + rows.join('') + '</tbody></table>');
      continue;
    }

    const buf = [];
    while (i < lines.length && !/^\s*$/.test(lines[i]) && !/^(#{1,6}\s|```|>|\s*[-*+]\s|\s*\d+[.)]\s)/.test(lines[i])) {
      buf.push(lines[i++]);
    }
    if (buf.length) out.push('<p>' + inline(buf.join(' ')) + '</p>');
  }

  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(titleText)}</title>
<style>
  :root{--text:#1c2128;--sub:#5f5e5a;--line:#e6e8ec;--code:#f6f7f9}
  *{box-sizing:border-box}
  body{margin:0;background:#fff;color:var(--text);font:15px/1.8 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
  .md{max-width:820px;margin:0 auto;padding:48px 24px 96px}
  h1,h2,h3,h4,h5,h6{line-height:1.4;margin:1.6em 0 .6em;font-weight:600}
  h1{font-size:26px;margin-top:0} h2{font-size:21px;border-bottom:1px solid var(--line);padding-bottom:.3em}
  h3{font-size:17px} h4{font-size:15px}
  p{margin:.8em 0}
  a{color:#1677ff;text-decoration:none} a:hover{text-decoration:underline}
  ul,ol{padding-left:1.6em;margin:.8em 0}
  li{margin:.3em 0}
  blockquote{margin:1em 0;padding:.6em 1em;border-left:3px solid #d3d1c7;background:#fafaf8;color:var(--sub)}
  code{background:var(--code);padding:.15em .4em;border-radius:4px;font-size:.9em;font-family:ui-monospace,Consolas,monospace}
  pre{background:var(--code);padding:16px;border-radius:8px;overflow:auto;line-height:1.6}
  pre code{background:none;padding:0;font-size:13px}
  img{max-width:100%;height:auto;border-radius:8px;margin:1em 0}
  hr{border:0;border-top:1px solid var(--line);margin:2em 0}
  table{border-collapse:collapse;width:100%;margin:1em 0;font-size:14px}
  th,td{border:1px solid var(--line);padding:8px 12px;text-align:left}
  th{background:#fafbfc;font-weight:500}
</style>
</head>
<body><div class="md">
${out.join('\n')}
</div></body></html>`;
}

/* ============================ 构建输出 ============================ */

function writeShell(dest, payload, iv, opt) {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, buildShell(payload, iv, opt), 'utf8');
}

function plainPathFor(file) {
  const rel = path.relative(ROOT, file);
  return path.join(PLAIN_DIR, rel);
}

function backupPlain(file) {
  const dest = plainPathFor(file);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(file, dest);
}

function encryptHtmlFile(file, password) {
  const buf = fs.readFileSync(file);
  const { payload, iv } = encryptBuf(buf, password);
  writeShell(file, payload, iv, { mode: 'html' });
  return buf.length;
}

function bundleFile(file, password, outArg) {
  const ext = path.extname(file).toLowerCase();
  const base = path.basename(file, ext);
  const buf = fs.readFileSync(file);
  let html, mode = 'html', downloadName = '', downloadMime = 'application/octet-stream', note = '';

  if (ext === '.md' || ext === '.markdown') {
    html = Buffer.from(mdToHtml(buf.toString('utf8'), base), 'utf8');
  } else if (['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp'].indexOf(ext) >= 0) {
    const mime = ext === '.svg' ? 'image/svg+xml' : ext === '.png' ? 'image/png' : ext === '.gif' ? 'image/gif' : ext === '.webp' ? 'image/webp' : ext === '.bmp' ? 'image/bmp' : 'image/jpeg';
    const b64 = buf.toString('base64');
    html = Buffer.from(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(base)}</title><style>html,body{margin:0;background:#f6f7f9}body{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px;box-sizing:border-box}img{max-width:100%;height:auto;box-shadow:0 4px 24px rgba(0,0,0,.08);border-radius:8px;background:#fff}</style></head><body><img alt="${escapeHtml(base)}" src="data:${mime};base64,${b64}"></body></html>`, 'utf8');
  } else {
    mode = 'download';
    downloadName = path.basename(file);
    downloadMime = ext === '.pdf' ? 'application/pdf'
      : ext === '.docx' ? 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
      : ext === '.xlsx' ? 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      : ext === '.pptx' ? 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
      : ext === '.zip' ? 'application/zip'
      : 'application/octet-stream';
    note = downloadName + ' · ' + humanSize(buf.length);
  }

  const payloadSrc = mode === 'html' ? html : buf;
  const { payload, iv } = encryptBuf(payloadSrc, password);
  const out = outArg || path.join(path.dirname(file), base + '加密.html');
  writeShell(out, payload, iv, { mode: mode, downloadName: downloadName, downloadMime: downloadMime, note: note });
  return { out: out, mode: mode };
}

/* ============================ 命令分发 ============================ */

function main() {
  const parsed = parseArgs(process.argv.slice(2));
  const cmd = parsed.rest[0];
  const password = getPassword(parsed.pass);

  if (cmd === 'all') {
    const files = [];
    (function walk(dir) {
      for (const name of fs.readdirSync(dir)) {
        const p = path.join(dir, name);
        const st = fs.statSync(p);
        if (st.isDirectory()) walk(p);
        else if (/\.html$/i.test(name)) files.push(p);
      }
    })(PLAIN_DIR);
    if (!files.length) fail('.plain-src 下没有 HTML，请先备份明文');
    files.forEach(function (p) {
      const rel = path.relative(PLAIN_DIR, p);
      const dest = path.join(ROOT, rel);
      const buf = fs.readFileSync(p);
      const { payload, iv } = encryptBuf(buf, password);
      writeShell(dest, payload, iv, { mode: 'html' });
      console.log('加密 ' + rel + '  (' + humanSize(buf.length) + ' → ' + humanSize(fs.statSync(dest).size) + ')');
    });
    console.log('完成：共 ' + files.length + ' 个页面');
    return;
  }

  if (cmd === 'encrypt') {
    const files = parsed.rest.slice(1);
    if (!files.length) fail('请指定要加密的 HTML 文件');
    files.forEach(function (f) {
      const abs = path.resolve(f);
      if (!fs.existsSync(abs)) fail('文件不存在：' + abs);
      backupPlain(abs);
      const n = encryptHtmlFile(abs, password);
      console.log('加密 ' + path.relative(ROOT, abs) + '  (' + humanSize(n) + ' 明文已备份到 .plain-src)');
    });
    return;
  }

  if (cmd === 'bundle') {
    const inputs = parsed.rest.slice(1);
    if (!inputs.length) fail('请指定要打包的文件（md / 图片 / pdf / office / zip）');
    inputs.forEach(function (f) {
      const abs = path.resolve(f);
      if (!fs.existsSync(abs)) fail('文件不存在：' + abs);
      const r = bundleFile(abs, password, inputs.length === 1 ? parsed.out : null);
      console.log('打包 ' + path.relative(ROOT, abs) + ' → ' + path.relative(ROOT, r.out) + '  (模式：' + r.mode + ')');
    });
    return;
  }

  console.log([
    'juanev 加密工具',
    '  node tools/encrypt.js all                    加密 .plain-src 下全部 HTML',
    '  node tools/encrypt.js encrypt <file...>      备份并原地加密 HTML',
    '  node tools/encrypt.js bundle <file...>       打包 md/图片/pdf/office 为加密页面',
    '  口令来源：--pass <口令> | 环境变量 JUANEV_PASS | ' + KEY_FILE
  ].join('\n'));
}

main();
