// Colour mode (light / dark / auto = follow the system). Loaded in <head> as a file (strict
// CSP: no inline scripts), before the page paints, so a dark page never flashes light.
// The choice is kept per browser; pspm.js wires the switch in the navigation bar.
(function () {
  'use strict';
  var KEY = 'pspm-theme';
  var media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  var mem = null;   // when the browser refuses storage (private mode): this page only
  function choice() {
    var v = mem;
    if (v === null) { try { v = localStorage.getItem(KEY); } catch (e) { v = null; } }
    return v === 'light' || v === 'dark' ? v : 'auto';
  }
  function apply() {
    var c = choice();
    var mode = c === 'auto' ? (media && media.matches ? 'dark' : 'light') : c;
    document.documentElement.setAttribute('data-bs-theme', mode);
    document.documentElement.setAttribute('data-pspm-theme-choice', c);
  }
  window.pspmTheme = {
    choice: choice,
    set: function (c) {
      try { if (c === 'auto') localStorage.removeItem(KEY); else localStorage.setItem(KEY, c); mem = null; } catch (e) { mem = c; }
      apply();
    }
  };
  if (media && media.addEventListener) media.addEventListener('change', function () { if (choice() === 'auto') apply(); });
  apply();
})();
