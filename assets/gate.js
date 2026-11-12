/*!
 * juanev 全站口令门 v1 —— 纯静态访问拦截
 * 机制：未通过校验时全屏遮罩拦截；口令经加盐 SHA-256 比对；
 *      通过后写入浏览器本地存储，30 天内免输；更换口令（HASH）后所有旧凭证自动失效。
 * 已知限制：前端拦截，禁用 JS / 查看源码可绕过（档位：防普通访客，非机密级防护）。
 * 换口令：重算 SHA-256("<SALT>:<新口令>")，替换下方 HASH；QUESTION 可改为提示问题文案。
 */
(function () {
  'use strict';

  /* ============ 配置区（改口令只动这里） ============ */
  var SALT = 'juanev-2026';
  var HASH = '14548417f0e4214f10e96b140bf138c2d1ce9188d142ea68bf56544342b89260'; // 加盐哈希
  var DAYS = 30;                    // 通过后免输天数
  var STORE_KEY = 'juanev_gate_v1'; // 本地存储键名
  var QUESTION = '请输入访问口令';   // 可改为提示问题，如「本项目对接的客户名称是？」
  var HINT = '';                    // 可选副提示文案
  /* ================================================= */

  var root = document.documentElement;

  function isUnlocked() {
    try {
      var raw = window.localStorage.getItem(STORE_KEY);
      if (!raw) return false;
      var v = JSON.parse(raw);
      return !!(v && v.h === HASH && typeof v.exp === 'number' && Date.now() < v.exp);
    } catch (e) { return false; }
  }

  function fallbackHash(s) {
    var h1 = 5381, h2 = 52711, i, c;
    for (i = 0; i < s.length; i++) {
      c = s.charCodeAt(i);
      h1 = (((h1 << 5) + h1 + c) >>> 0);
      h2 = (((h2 << 7) + h2 + c) >>> 0);
    }
    return 'fb-' + h1.toString(16) + '-' + h2.toString(16);
  }

  function hash(text) {
    if (window.crypto && window.crypto.subtle && window.TextEncoder) {
      return window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
        .then(function (buf) {
          return Array.prototype.map.call(new Uint8Array(buf), function (b) {
            return ('0' + b.toString(16)).slice(-2);
          }).join('');
        });
    }
    return Promise.resolve(fallbackHash(text));
  }

  function reveal() {
    root.style.visibility = '';
    var g = document.getElementById('juanev-gate');
    if (g && g.parentNode) g.parentNode.removeChild(g);
  }

  function buildGate() {
    if (document.getElementById('juanev-gate')) return;
    var style = document.createElement('style');
    style.textContent = [
      '#juanev-gate{position:fixed;top:0;right:0;bottom:0;left:0;z-index:2147483000;background:#f1efe8;',
      'visibility:visible;display:flex;align-items:center;justify-content:center;',
      'font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;}',
      '#juanev-gate .jg-card{background:#fff;border:1px solid rgba(0,0,0,.15);border-radius:12px;',
      'padding:28px 24px;width:340px;max-width:88vw;box-sizing:border-box;}',
      '#juanev-gate .jg-title{font-size:15px;font-weight:500;color:#2c2c2a;margin:0 0 6px;text-align:center;}',
      '#juanev-gate .jg-hint{font-size:12px;color:#888780;margin:0 0 14px;text-align:center;}',
      '#juanev-gate .jg-input{width:100%;box-sizing:border-box;border:1px solid rgba(0,0,0,.3);border-radius:8px;',
      'padding:10px 12px;font-size:14px;outline:none;}',
      '#juanev-gate .jg-input:focus{border-color:#185fa5;}',
      '#juanev-gate .jg-err{border-color:#e24b4a !important;}',
      '#juanev-gate .jg-msg{font-size:12px;color:#a32d2d;min-height:16px;margin:8px 0 0;text-align:center;}',
      '#juanev-gate .jg-btn{width:100%;margin-top:12px;background:#185fa5;color:#fff;border:0;border-radius:8px;',
      'padding:10px 0;font-size:14px;cursor:pointer;}',
      '#juanev-gate .jg-btn:active{background:#0c447c;}'
    ].join('');
    document.head.appendChild(style);

    var wrap = document.createElement('div');
    wrap.id = 'juanev-gate';
    wrap.innerHTML =
      '<div class="jg-card">' +
        '<p class="jg-title"></p>' +
        (HINT ? '<p class="jg-hint"></p>' : '') +
        '<input class="jg-input" type="password" autocomplete="off" placeholder="口令">' +
        '<p class="jg-msg"></p>' +
        '<button class="jg-btn" type="button">进入</button>' +
      '</div>';
    wrap.querySelector('.jg-title').textContent = QUESTION;
    if (HINT) wrap.querySelector('.jg-hint').textContent = HINT;
    document.body.appendChild(wrap);

    var input = wrap.querySelector('.jg-input');
    var msg = wrap.querySelector('.jg-msg');
    var btn = wrap.querySelector('.jg-btn');

    function fail(text) {
      msg.textContent = text;
      input.classList.add('jg-err');
      input.focus();
      input.select();
    }

    function submit() {
      var val = input.value;
      if (!val) { fail('请输入口令'); return; }
      input.classList.remove('jg-err');
      msg.textContent = '校验中…';
      hash(SALT + ':' + val).then(function (hex) {
        if (hex === HASH) {
          try {
            window.localStorage.setItem(STORE_KEY, JSON.stringify({
              h: HASH,
              exp: Date.now() + DAYS * 864e5
            }));
          } catch (e) { /* 存储不可用时仅本次放行 */ }
          wrap.parentNode.removeChild(wrap);
          reveal();
        } else {
          fail('口令不正确，请重试');
        }
      }).catch(function () {
        fail('校验异常，请刷新重试');
      });
    }

    btn.addEventListener('click', submit);
    input.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter') submit();
    });
    setTimeout(function () { input.focus(); }, 50);
  }

  // 兜底：任何未捕获错误都恢复显示，避免遮罩未建成时页面永久空白
  window.addEventListener('error', function () { reveal(); });

  if (isUnlocked()) {
    reveal();
    return;
  }

  root.style.visibility = 'hidden';

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', buildGate);
  } else {
    buildGate();
  }
})();
