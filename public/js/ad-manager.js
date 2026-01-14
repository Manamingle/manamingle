// Lightweight Ad Manager: popup + footer placeholder
(() => {
  const css = `
    .mm-ad-popup {
      position: fixed;
      bottom: 20px;
      right: 20px;
      width: 320px;
      max-width: calc(100vw - 40px);
      background: rgba(255,255,255,0.06);
      border: 1px solid var(--border, rgba(255,255,255,0.1));
      border-radius: 16px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.3);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      color: var(--light, #f8fafc);
      z-index: 2000;
      display: none;
      overflow: hidden;
      animation: mm-slide-in .25s ease-out;
    }
    @keyframes mm-slide-in { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
    .mm-ad-header {
      display: flex; align-items: center; justify-content: space-between;
      padding: 10px 12px; border-bottom: 1px solid var(--border, rgba(255,255,255,0.1));
    }
    .mm-ad-title { font-weight: 700; font-size: 0.95rem; }
    .mm-ad-close {
      width: 28px; height: 28px; border-radius: 8px;
      border: 1px solid var(--border, rgba(255,255,255,0.1));
      background: rgba(255,255,255,0.08); color: var(--light, #f8fafc);
      display: flex; align-items: center; justify-content: center; cursor: pointer;
      transition: transform .2s ease, background .2s ease;
    }
    .mm-ad-close:hover { transform: scale(1.05); background: rgba(255,255,255,0.12); }
    .mm-ad-body { padding: 10px 12px; display: flex; gap: 12px; align-items: center; }
    .mm-ad-thumb {
      width: 64px; height: 64px; border-radius: 12px; overflow: hidden;
      background: linear-gradient(135deg, rgba(0,102,204,.2), rgba(0,209,154,.2));
      position: relative;
    }
    .mm-shimmer::after {
      content: ''; position: absolute; inset: 0;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
      animation: mm-shimmer 1.4s infinite;
    }
    @keyframes mm-shimmer { from { transform: translateX(-100%); } to { transform: translateX(100%); } }
    .mm-ad-text { flex: 1; font-size: 0.9rem; color: var(--light, #f8fafc); opacity: .9; }
    .mm-footer-ad {
      position: fixed; left: 0; right: 0; bottom: 0; height: 80px;
      background: rgba(255,255,255,0.05); border-top: 1px solid var(--border, rgba(255,255,255,0.1));
      backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
      z-index: 1500; display: flex; align-items: center; justify-content: center;
    }
    .mm-footer-content {
      display: flex; align-items: center; gap: 12px; padding: 0 16px;
      border-radius: 14px; border: 1px solid var(--border, rgba(255,255,255,0.1));
      background: rgba(255,255,255,0.06); height: 48px;
    }
    .mm-footer-logo {
      width: 28px; height: 28px; border-radius: 8px;
      background: linear-gradient(135deg, #0066cc, #00d19a);
      box-shadow: 0 0 12px rgba(0, 209, 154, 0.3);
    }
    .mm-footer-text { font-weight: 600; font-size: .95rem; color: var(--light, #f8fafc); }
  `;
  function injectCSS() {
    if (document.getElementById('mm-ad-style')) return;
    const s = document.createElement('style');
    s.id = 'mm-ad-style';
    s.textContent = css;
    document.head.appendChild(s);
  }
  function createFooterAd() {
    if (document.getElementById('mm-footer-ad')) return;
    const el = document.createElement('div');
    el.id = 'mm-footer-ad';
    el.className = 'mm-footer-ad';
    el.innerHTML = `
      <div class="mm-footer-content mm-shimmer">
        <div class="mm-footer-logo"></div>
        <div class="mm-footer-text">Ad Placeholder • Your content here</div>
      </div>
    `;
    document.body.appendChild(el);
    try {
      const currentPad = parseInt(getComputedStyle(document.body).paddingBottom || '0', 10) || 0;
      document.body.style.paddingBottom = Math.max(currentPad, 90) + 'px';
    } catch (_) {}
  }
  function createPopupAd() {
    if (sessionStorage.getItem('mmAdClosed') === '1') return;
    if (document.getElementById('mm-ad-popup')) return;
    const el = document.createElement('div');
    el.id = 'mm-ad-popup';
    el.className = 'mm-ad-popup';
    el.innerHTML = `
      <div class="mm-ad-header">
        <div class="mm-ad-title">Sponsored</div>
        <button class="mm-ad-close" aria-label="Close">✕</button>
      </div>
      <div class="mm-ad-body">
        <div class="mm-ad-thumb mm-shimmer"></div>
        <div class="mm-ad-text">Promote your brand here with a non‑intrusive popup. Click to learn more.</div>
      </div>
    `;
    const closeBtn = el.querySelector('.mm-ad-close');
    closeBtn.addEventListener('click', () => {
      sessionStorage.setItem('mmAdClosed', '1');
      el.remove();
    });
    document.body.appendChild(el);
    el.style.display = 'block';
  }
  function init() {
    injectCSS();
    createFooterAd();
    setTimeout(createPopupAd, 4000);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
