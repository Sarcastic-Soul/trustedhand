/* Approval page for Ravi. Link: approve.html#r=<request_id>&t=<token>
   The token comes from the URL fragment (never sent in an access log), is kept
   only in memory, goes in a request header or body, and is never logged. */
(function () {
  'use strict';
  var TH = window.TH, h = TH.h, icon = TH.icon, api = TH.api;
  var view = document.getElementById('view');

  var link = TH.parseLink('#' + location.hash.replace(/^#/, ''));
  var rid = link && link.r, token = link && link.t;

  function show() { view.replaceChildren.apply(view, arguments); }

  function resultBox(kind, iconName, title, lines, extra) {
    return h('div', { class: 'result ' + kind, role: 'status' },
      h('h2', null, icon(iconName), title),
      lines.map(function (l) { return h('p', { text: l }); }),
      extra || null);
  }

  function errorView(e) {
    var map = {
      forbidden: ['This link is not valid', 'It may have been used already, or it was mistyped. Ask Amma to send the request again.'],
      auth: ['This link is not valid', 'It may have been used already, or it has expired. Ask Amma to send the request again.'],
      notfound: ['We cannot find this request', 'It may have expired (requests last 72 hours). Nothing was paid.'],
      rate: ['Too many tries', e.message || 'Please wait a few minutes and try again.']
    };
    var m = map[e.kind] || ['Something went wrong', e.message || 'Please try again.'];
    var again = (e.kind === 'network' || e.kind === 'timeout' || e.kind === 'server' || e.kind === 'rate')
      ? h('button', { type: 'button', class: 'btn', onclick: load }, icon('arrow-clockwise'), 'Try again') : null;
    show(resultBox('warn', 'warning', m[0], [m[1]], again));
  }

  function statusView(status) {
    if (status === 'approved') {
      show(resultBox('ok', 'check-circle', 'Already approved', [
        'You approved this request. The money can move after the cool-off. Nothing else is needed.']));
    } else if (status === 'denied') {
      show(resultBox('no', 'x-circle', 'Already denied', ['You denied this request. Nothing will be paid.']));
    } else {
      show(resultBox('warn', 'clock-countdown', 'This request has expired', [
        'Nobody answered in time, so nothing was paid. If it is still needed, Amma can ask again.']));
    }
  }

  function detailsView(req) {
    var acct = req.account_masked || TH.maskAcct(req.account);
    var errLine = h('p', { class: 'ask-result err', role: 'alert' });
    var yes = h('button', { type: 'button', class: 'btn btn-primary' }, icon('check'), 'Approve');
    var no = h('button', { type: 'button', class: 'btn btn-deny' }, icon('x'), 'Deny');

    function decide(decision) {
      yes.disabled = no.disabled = true;
      errLine.textContent = '';
      api('/approval/' + encodeURIComponent(rid), { method: 'POST', body: { token: token, decision: decision }, timeout: 20000 })
        .then(function () {
          if (decision === 'approve') {
            show(resultBox('ok', 'check-circle', 'Approved', [
              'Thank you. Nothing is paid right now.',
              'The money can move after the cool-off: 24 hours in real use, 2 minutes in a demo household. This approval covers only this payee, this account and this amount.']));
          } else {
            show(resultBox('no', 'x-circle', 'Denied', ['Thank you. Nothing will be paid.']));
          }
        })
        .catch(function (e) {
          yes.disabled = no.disabled = false;
          if (e.kind === 'forbidden' || e.kind === 'auth' || e.kind === 'notfound') errorView(e);
          else errLine.textContent = e.message;
        });
    }
    yes.addEventListener('click', function () { decide('approve'); });
    no.addEventListener('click', function () { decide('deny'); });

    var dl = h('dl', null,
      h('dt', { text: 'Pay to' }), h('dd', { text: req.payee_name || req.payee || '' }),
      acct ? [h('dt', { text: 'Account' }), h('dd', { class: 'mono', text: acct })] : null,
      req.reason ? [h('dt', { text: 'Reason given' }), h('dd', { text: req.reason })] : null,
      req.created_at ? [h('dt', { text: 'Asked at' }), h('dd', { text: TH.fmtDateTime(req.created_at) })] : null);

    show(
      h('p', { class: 'lede', text: 'Nothing has been paid. It will only be paid if you approve.' }),
      h('div', { class: 'ap-card' },
        h('div', { class: 'ap-amount' }, h('span', { class: 'label', text: 'Amount' }), h('span', { class: 'num', text: TH.inr(req.amount_inr) })),
        dl),
      h('div', { class: 'callout' },
        h('strong', { text: 'Check before you approve' }),
        'Only approve if you know this person and Amma asked you herself, by talking to you. Scammers often tell people to ask a family member to approve. If in doubt, deny and call Amma.'),
      h('div', { class: 'ap-actions' }, yes, no),
      errLine,
      h('p', { class: 'start-fine', text: 'After you approve, the money can move only after a cool-off (24 hours; 2 minutes in a demo household).' }));
  }

  function load() {
    show(h('p', { class: 'loading' }, icon('circle-notch'), 'Opening your request…'));
    api('/approval/' + encodeURIComponent(rid), { headers: { 'x-approval-token': token }, timeout: 20000 })
      .then(function (req) {
        req = req || {};
        if (req.status && req.status !== 'pending') statusView(req.status);
        else detailsView(req);
      })
      .catch(errorView);
  }

  window.addEventListener('hashchange', function () { location.reload(); });

  if (!rid || !token) {
    show(resultBox('warn', 'link-break', 'This link is incomplete', [
      'Open the full link from your message. It should end with the request code and a one-time key.']));
  } else {
    load();
  }
})();
