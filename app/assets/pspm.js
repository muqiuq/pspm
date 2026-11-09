// PSPM UI behaviour. Loaded as a file (strict CSP: no inline scripts).
(function () {
  'use strict';

  // QR code for TOTP enrolment, drawn locally (the secret never leaves the browser).
  var qr = document.getElementById('qr');
  if (qr && window.qrcode) {
    var q = window.qrcode(0, 'M');
    q.addData(qr.getAttribute('data-otpauth'));
    q.make();
    var img = document.createElement('img');
    img.src = q.createDataURL(5, 2);
    img.alt = 'QR code for your authenticator app';
    qr.appendChild(img);
  }

  // Repeatable rows: <div data-rows="x"> + <template data-template="x"> + [data-add-row="x"].
  var counter = 1000;
  document.addEventListener('click', function (e) {
    var t = e.target;
    var add = t.closest('[data-add-row]');
    if (add) {
      var name = add.getAttribute('data-add-row');
      var tpl = document.querySelector('template[data-template="' + name + '"]');
      var box = document.querySelector('[data-rows="' + name + '"]');
      if (tpl && box) {
        var html = tpl.innerHTML.replace(/__i__/g, String(counter++));
        box.insertAdjacentHTML('beforeend', html);
      }
      return;
    }
    var rm = t.closest('[data-remove-row]');
    if (rm) { var row = rm.closest('[data-row]'); if (row) row.remove(); return; }
    var mv = t.closest('[data-move]');
    if (mv) {
      var r = mv.closest('[data-row]');
      if (mv.getAttribute('data-move') === 'up' && r.previousElementSibling) r.parentNode.insertBefore(r, r.previousElementSibling);
      if (mv.getAttribute('data-move') === 'down' && r.nextElementSibling) r.parentNode.insertBefore(r.nextElementSibling, r);
      return;
    }
    var cp = t.closest('[data-copy]');
    if (cp) {
      var src = document.querySelector(cp.getAttribute('data-copy'));
      if (src) {
        src.select();
        if (navigator.clipboard) navigator.clipboard.writeText(src.value); else document.execCommand('copy');
        var old = cp.textContent; cp.textContent = 'Copied'; setTimeout(function () { cp.textContent = old; }, 1500);
      }
    }
  });

  // Confirmation for dangerous buttons: <form data-confirm="…">.
  document.addEventListener('submit', function (e) {
    var f = e.target;
    var msg = f.getAttribute && f.getAttribute('data-confirm');
    if (msg && !window.confirm(msg)) e.preventDefault();
  });

  // Access policy presets fill in the condition checkboxes.
  document.querySelectorAll('[data-preset-target]').forEach(function (sel) {
    sel.addEventListener('change', function () {
      if (!sel.value) return;
      var want = sel.value.split(',');
      document.querySelectorAll('input[name="conditions[]"]').forEach(function (cb) { cb.checked = want.indexOf(cb.value) >= 0; });
    });
  });

  if (window.bootstrap) document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (el) { new window.bootstrap.Tooltip(el); });
})();
