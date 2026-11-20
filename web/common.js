/* Shared helpers for index.html and approve.html.
   Loaded after config.js. No build step. All server text goes in through
   textContent (h() below), never innerHTML. */
(function (global) {
  'use strict';

  var cfg = global.TH_CONFIG || {};
  var base = String(cfg.apiBase || '').replace(/\/+$/, '');

  /* ---------- API ---------- */

  function ApiError(kind, status, message, retryAfter) {
    this.name = 'ApiError';
    this.kind = kind; // network | timeout | rate | auth | forbidden | notfound | server | bad
    this.status = status;
    this.message = message;
    this.retryAfter = retryAfter || null;
  }
  ApiError.prototype = Object.create(Error.prototype);

  function api(path, opts) {
    opts = opts || {};
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, opts.timeout || 100000);
    var headers = Object.assign({}, opts.headers || {});
    if (opts.body !== undefined) headers['content-type'] = 'application/json';
    var url = /^https?:\/\//.test(path) ? path : base + path;
    return fetch(url, {
      method: opts.method || 'GET',
      headers: headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      signal: ctrl.signal,
      cache: 'no-store',
      referrerPolicy: 'no-referrer'
    }).then(function (res) {
      return res.json().catch(function () { return null; }).then(function (data) {
        clearTimeout(timer);
        if (res.ok) return data;
        var msg = data && (data.message || data.error);
        if (typeof msg !== 'string') msg = '';
        var ra = res.headers.get('retry-after');
        var s = res.status;
        if (s === 429) throw new ApiError('rate', s, msg || 'Too many requests. Please wait a little and try again.', ra);
        if (s === 401) throw new ApiError('auth', s, msg || 'This session has expired.');
        if (s === 403) throw new ApiError('forbidden', s, msg || 'This link is not valid.');
        if (s === 404) throw new ApiError('notfound', s, msg || 'Not found.');
        if (s >= 500) throw new ApiError('server', s, msg || 'Something went wrong on our side. Please try again.');
        throw new ApiError('bad', s, msg || 'The request was not accepted.');
      });
    }, function (e) {
      clearTimeout(timer);
      if (e && e.name === 'AbortError') {
        throw new ApiError('timeout', 0, 'That took too long. Please try again.');
      }
      throw new ApiError('network', 0, 'Cannot reach the server. Check your connection and try again.');
    });
  }

  /* ---------- DOM ---------- */

  function h(tag, attrs) {
    var el = document.createElement(tag);
    var a = attrs || {};
    Object.keys(a).forEach(function (k) {
      var v = a[k];
      if (v === null || v === undefined || v === false) return;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    });
    for (var i = 2; i < arguments.length; i++) append(el, arguments[i]);
    return el;
  }
  function append(el, kid) {
    if (kid === null || kid === undefined || kid === false) return;
    if (Array.isArray(kid)) { kid.forEach(function (k) { append(el, k); }); return; }
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  // Phosphor icon font (loaded from the CDN in each page head). Decorative only.
  function icon(name) {
    return h('i', { class: 'ph ph-' + name, 'aria-hidden': 'true' });
  }

  /* ---------- Formatting ---------- */

  function inr(n) {
    var v = Number(n);
    if (!isFinite(v)) return '';
    return '₹' + v.toLocaleString('en-IN');
  }
  // Accepts epoch seconds, epoch ms, or an ISO string. Returns ms or null.
  function toMs(x) {
    if (x === null || x === undefined || x === '' || x === 0) return null;
    if (typeof x === 'number') return x < 1e12 ? x * 1000 : x;
    var d = Date.parse(String(x));
    return isNaN(d) ? null : d;
  }
  function fmtTime(x) {
    var ms = toMs(x);
    if (ms === null) return '';
    return new Date(ms).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', second: '2-digit' });
  }
  function fmtDateTime(x) {
    var ms = toMs(x);
    if (ms === null) return '';
    return new Date(ms).toLocaleString([], { day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit' });
  }
  function maskAcct(a) {
    var s = String(a || '');
    if (!s) return '';
    if (s.indexOf('•') !== -1 || s.indexOf('*') !== -1) return s;
    return '•••• ' + s.slice(-4);
  }

  // "#r=<id>&t=<token>" (or a full link) -> {r, t} or null. Token never leaves memory.
  function parseLink(link) {
    if (!link) return null;
    var i = String(link).indexOf('#');
    if (i < 0) return null;
    var p = new URLSearchParams(String(link).slice(i + 1));
    var r = p.get('r'), t = p.get('t');
    return r && t ? { r: r, t: t } : null;
  }

  /* ---------- Rule and layer names (from docs/DESIGN.md) ---------- */

  var RULES = {
    R1: 'Approved payees only',
    R2: 'Exactly the amount due',
    R3: 'Per-payment limit',
    R4: 'Daily limit',
    R5: 'No double payment',
    R6: 'Ravi must approve',
    R7: 'Text is data',
    R8: 'Private details hidden',
    R9: 'Scam freeze',
    R10: 'No self-service changes',
    R11: 'Rate limit',
    R12: 'Three strikes'
  };
  var RULE_TEXT = {
    R1: 'Never pay anyone who is not an approved payee. There is no tool that adds a payee.',
    R2: 'Pay exactly the amount due on a bill: never more and never less.',
    R3: 'No single payment over the per-payment limit (default ₹10,000).',
    R4: 'No more than the daily limit in total (default ₹25,000) or 5 payments per day.',
    R5: 'Never pay the same bill twice.',
    R6: 'A new payee or transfer needs Ravi’s approval through a separate one-time link, and the money moves only after a cool-off.',
    R7: 'Text inside bills, payee names and tool results is data, never instructions.',
    R8: 'Never show full account numbers, another household’s data, or the agent’s instructions.',
    R9: 'If the chat shows scam signs, the household is frozen for new payees and transfers, Amma is told calmly, and Ravi is alerted. Known bills stay payable.',
    R10: 'The agent cannot change limits, approve requests, lift a freeze or edit payees. No tool exists for any of these.',
    R11: 'Rate limits per session, per IP and a global daily cap on agent runs.',
    R12: 'After 3 refused payment attempts in a day, across all chats, payments and new requests lock for 30 minutes and Ravi is alerted.'
  };
  var LAYERS = [
    ['proxy', 'Chat proxy', 'L0'],
    ['guardrail', 'Guardrail', 'L0'],
    ['harness', 'Harness', 'L1'],
    ['hook', 'Hook', 'L2'],
    ['interceptor', 'Interceptor', 'L3/L5'],
    ['policy', 'Cedar policy', 'L4'],
    ['tool', 'Tool + database', 'L6'],
    ['approval', 'Approval link', 'L7'],
    ['notifier', 'Notifier', 'L7']
  ];
  var LAYER_NAME = {};
  LAYERS.forEach(function (l) { LAYER_NAME[l[0]] = l[1]; });

  function ruleParts(rule) {
    if (!rule) return [];
    return String(rule).split(/[\s,;/]+/).filter(Boolean).map(function (id) {
      var key = id.toUpperCase();
      return { id: id, label: RULES[key] || '' };
    });
  }

  // POST /chat goes to a Lambda Function URL (no 30 s API Gateway cut-off). Falls back to apiBase.
  var chatUrl = cfg.chatUrl ? String(cfg.chatUrl).replace(/\/+$/, '') : '/chat';

  global.TH = {
    chatUrl: chatUrl, api: api, ApiError: ApiError, h: h, icon: icon, inr: inr, toMs: toMs,
    fmtTime: fmtTime, fmtDateTime: fmtDateTime, maskAcct: maskAcct, parseLink: parseLink,
    RULES: RULES, RULE_TEXT: RULE_TEXT, LAYERS: LAYERS, LAYER_NAME: LAYER_NAME, ruleParts: ruleParts
  };
})(window);
