(() => {
  let promptEvent = null;
  const installed = () => window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
  const update = () => {
    const button = document.getElementById('install-app');
    if (!button) return;
    button.hidden = installed() || !promptEvent;
    const status = document.getElementById('install-status');
    if (installed()) status.textContent = 'TONA ilova oynasida ochilgan.';
  };
  window.addEventListener('beforeinstallprompt', event => { event.preventDefault(); promptEvent = event; update(); });
  window.addEventListener('appinstalled', () => { promptEvent = null; update(); });
  document.addEventListener('click', async event => {
    if (event.target.id !== 'install-app' || !promptEvent) return;
    const pending = promptEvent;
    promptEvent = null;
    try { await pending.prompt(); await pending.userChoice; }
    catch { document.getElementById('install-status').textContent = 'Brauzer menyusidagi o‘rnatish imkoniyatidan foydalaning.'; }
    update();
  });
  if ('serviceWorker' in navigator && window.isSecureContext) {
    navigator.serviceWorker.register('/sw.js', {scope:'/'}).catch(() => {
      const status = document.getElementById('install-status');
      if (status) status.textContent = 'O‘rnatish tayyorlanmadi. Internetni tekshirib, sahifani yangilang.';
    });
  }
  update();
})();
