// ---------------- boot ----------------
// Live mode when this page is served by the MCPWarden backend; otherwise the original in-browser demo.
(async function boot() {
  applyTheme();
  $('#root').innerHTML = '<div style="display:grid;place-items:center;height:100%;color:var(--muted)">Starting MCPWarden…</div>';
  const health = await LiveClient.detect();
  if (health) {
    try { await LiveClient.start(health); }
    catch (e) { $('#root').innerHTML = `<div class="empty" style="margin:40px"><b>The MCPWarden backend did not respond</b>${esc(e.message)}. Live mode is not active and no security events are being shown.</div>`; return; }
    route(); return;
  }
  try {
    Warden.init();
    await Registry.boot();
  } catch (e) { $('#root').innerHTML = `<div class="empty" style="margin:40px"><b>MCPWarden could not start</b>${esc(e.message)}</div>`; return; }
  route();
})();
