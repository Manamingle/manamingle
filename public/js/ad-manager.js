// Production-Ready Ad Manager: Popup + Footer Placeholder
// Error-free with comprehensive error handling and fallbacks
(() => {
  'use strict';

  // =========== CONFIGURATION ===========
  const CONFIG = {
    CACHE_DURATION: 60000, // 1 minute
    DEFAULT_FREQUENCY: 10, // minutes
    DEFAULT_CLICKS_THRESHOLD: 3,
    POPUP_DELAY: 4000, // 4 seconds
    SESSION_KEYS: {
      AD_CLOSED: 'mmAdClosed',
      CLICKS: 'mm_clicks',
      LAST_AD_TS: 'mm_lastAdTs'
    },
    COOKIE_ADFREE: 'mm_adfree'
  };

  // =========== STYLES ===========
  const CSS = `
    /* Popup Ad Styles */
    .mm-ad-popup {
      position: fixed;
      bottom: 20px;
      right: 20px;
      width: clamp(280px, 90vw, 360px);
      max-width: calc(100vw - 40px);
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid var(--border, rgba(255, 255, 255, 0.1));
      border-radius: 16px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      color: var(--light, #f8fafc);
      z-index: 2000;
      display: none;
      overflow: hidden;
      animation: mm-slide-in 0.3s ease-out;
      transition: opacity 0.2s ease-out, transform 0.2s ease-out;
    }
    
    .mm-ad-popup.mm-closing {
      opacity: 0;
      transform: translateY(20px);
    }
    
    @keyframes mm-slide-in {
      from {
        transform: translateY(20px);
        opacity: 0;
      }
      to {
        transform: translateY(0);
        opacity: 1;
      }
    }
    
    /* Header */
    .mm-ad-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 10px 12px;
      border-bottom: 1px solid var(--border, rgba(255, 255, 255, 0.1));
      background: rgba(255, 255, 255, 0.03);
    }
    
    .mm-ad-title {
      font-weight: 700;
      font-size: 0.95rem;
      color: var(--light, #f8fafc);
      display: flex;
      align-items: center;
      gap: 6px;
    }
    
    .mm-ad-badge {
      font-size: 0.7rem;
      padding: 2px 6px;
      border-radius: 4px;
      background: rgba(59, 130, 246, 0.2);
      border: 1px solid rgba(59, 130, 246, 0.3);
      color: #60a5fa;
    }
    
    .mm-ad-close {
      width: 28px;
      height: 28px;
      border-radius: 8px;
      border: 1px solid var(--border, rgba(255, 255, 255, 0.1));
      background: rgba(255, 255, 255, 0.08);
      color: var(--light, #f8fafc);
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: transform 0.2s ease, background 0.2s ease;
      font-size: 16px;
      font-weight: 600;
    }
    
    .mm-ad-close:hover {
      transform: scale(1.05);
      background: rgba(255, 255, 255, 0.12);
    }
    
    .mm-ad-close:active {
      transform: scale(0.95);
    }
    
    /* Body */
    .mm-ad-body {
      padding: 12px;
      display: flex;
      gap: 12px;
      align-items: center;
      cursor: pointer;
      transition: background 0.2s ease;
    }
    
    .mm-ad-body:hover {
      background: rgba(255, 255, 255, 0.03);
    }
    
    .mm-ad-thumb {
      width: 64px;
      height: 64px;
      border-radius: 12px;
      overflow: hidden;
      background: linear-gradient(135deg, rgba(0, 102, 204, 0.2), rgba(0, 209, 154, 0.2));
      position: relative;
      flex-shrink: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 28px;
    }
    
    .mm-shimmer::after {
      content: '';
      position: absolute;
      inset: 0;
      background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
      animation: mm-shimmer 1.4s infinite;
    }
    
    @keyframes mm-shimmer {
      from { transform: translateX(-100%); }
      to { transform: translateX(100%); }
    }
    
    .mm-ad-text {
      flex: 1;
      font-size: 0.9rem;
      color: var(--light, #f8fafc);
      opacity: 0.9;
      line-height: 1.4;
    }
    
    /* Footer Ad */
    .mm-footer-ad {
      position: fixed;
      left: 0;
      right: 0;
      bottom: 0;
      height: 80px;
      background: rgba(255, 255, 255, 0.05);
      border-top: 1px solid var(--border, rgba(255, 255, 255, 0.1));
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      z-index: 1500;
      display: flex;
      align-items: center;
      justify-content: center;
      animation: mm-footer-slide-in 0.3s ease-out;
    }
    
    @keyframes mm-footer-slide-in {
      from {
        transform: translateY(100%);
      }
      to {
        transform: translateY(0);
      }
    }
    
    .mm-footer-content {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 0 16px;
      border-radius: 14px;
      border: 1px solid var(--border, rgba(255, 255, 255, 0.1));
      background: rgba(255, 255, 255, 0.06);
      height: 48px;
      cursor: pointer;
      transition: transform 0.2s ease, background 0.2s ease;
    }
    
    .mm-footer-content:hover {
      transform: scale(1.02);
      background: rgba(255, 255, 255, 0.08);
    }
    
    .mm-footer-logo {
      width: 28px;
      height: 28px;
      border-radius: 8px;
      background: linear-gradient(135deg, #0066cc, #00d19a);
      box-shadow: 0 0 12px rgba(0, 209, 154, 0.3);
      flex-shrink: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 14px;
    }
    
    .mm-footer-text {
      font-weight: 600;
      font-size: 0.95rem;
      color: var(--light, #f8fafc);
    }
    
    /* Mobile Responsive */
    @media (max-width: 640px) {
      .mm-ad-popup {
        bottom: 10px;
        right: 10px;
        left: 10px;
        width: auto;
        max-width: none;
      }
      
      .mm-footer-ad {
        height: clamp(52px, 10vh, 60px);
      }
      
      .mm-footer-content {
        height: 40px;
        padding: 0 12px;
      }
      
      .mm-footer-logo {
        width: 24px;
        height: 24px;
      }
      
      .mm-footer-text {
        font-size: 0.85rem;
      }
    }
    @media (max-height: 500px) {
      .mm-ad-popup { top: 10px; bottom: auto; }
    }
  `;

  // =========== STATE ===========
  let cachedConfig = null;
  let lastConfigFetch = 0;
  let initializationComplete = false;

  // =========== UTILITY FUNCTIONS ===========
  
  /**
   * Safely get sessionStorage value
   */
  function getSessionItem(key, defaultValue = null) {
    try {
      return sessionStorage.getItem(key) || defaultValue;
    } catch (error) {
      console.warn('[ManaAds] SessionStorage access failed:', error);
      return defaultValue;
    }
  }

  /**
   * Safely set sessionStorage value
   */
  function setSessionItem(key, value) {
    try {
      sessionStorage.setItem(key, value);
      return true;
    } catch (error) {
      console.warn('[ManaAds] SessionStorage write failed:', error);
      return false;
    }
  }

  /**
   * Check if ad-free mode is enabled via cookie
   */
  function isAdFreeEnabled() {
    try {
      return document.cookie && new RegExp(`${CONFIG.COOKIE_ADFREE}=true`).test(document.cookie);
    } catch (error) {
      console.warn('[ManaAds] Cookie check failed:', error);
      return false;
    }
  }

  /**
   * Safely parse integer
   */
  function safeParseInt(value, defaultValue = 0) {
    try {
      const parsed = parseInt(value, 10);
      return isNaN(parsed) ? defaultValue : parsed;
    } catch {
      return defaultValue;
    }
  }

  /**
   * Inject CSS styles
   */
  function injectCSS() {
    try {
      if (document.getElementById('mm-ad-style')) return;
      
      const styleEl = document.createElement('style');
      styleEl.id = 'mm-ad-style';
      styleEl.textContent = CSS;
      
      (document.head || document.documentElement).appendChild(styleEl);
      console.log('[ManaAds] Styles injected');
    } catch (error) {
      console.error('[ManaAds] Failed to inject CSS:', error);
    }
  }

  /**
   * Get ad configuration from server
   */
  async function getConfig() {
    const now = Date.now();
    
    // Return cached config if still valid
    if (cachedConfig && (now - lastConfigFetch) < CONFIG.CACHE_DURATION) {
      return cachedConfig;
    }
    
    try {
      const response = await fetch('/api/ads/config', {
        method: 'GET',
        headers: {
          'Accept': 'application/json'
        },
        cache: 'no-cache'
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
      const config = await response.json();
      
      // Validate config
      cachedConfig = {
        enabled: Boolean(config.enabled),
        frequency: safeParseInt(config.frequency, CONFIG.DEFAULT_FREQUENCY),
        clicksThreshold: safeParseInt(config.clicksThreshold, CONFIG.DEFAULT_CLICKS_THRESHOLD),
        type: config.type || 'placeholder',
        placeholderContent: config.placeholderContent || '',
        adsenseClientId: config.adsenseClientId || '',
        adsenseSlotId: config.adsenseSlotId || ''
      };
      
      lastConfigFetch = now;
      console.log('[ManaAds] Config loaded:', cachedConfig);
      return cachedConfig;
      
    } catch (error) {
      console.warn('[ManaAds] Failed to fetch config:', error);
      
      // Return default config on error
      cachedConfig = {
        enabled: false,
        frequency: CONFIG.DEFAULT_FREQUENCY,
        clicksThreshold: CONFIG.DEFAULT_CLICKS_THRESHOLD,
        type: 'placeholder'
      };
      
      lastConfigFetch = now;
      return cachedConfig;
    }
  }

  // =========== AD CREATION ===========
  
  /**
   * Create footer ad
   */
  function createFooterAd() {
    try {
      // Check if already exists
      if (document.getElementById('mm-footer-ad')) {
        console.log('[ManaAds] Footer ad already exists');
        return;
      }
      
      const footerAd = document.createElement('div');
      footerAd.id = 'mm-footer-ad';
      footerAd.className = 'mm-footer-ad';
      footerAd.innerHTML = `
        <div class="mm-footer-content mm-shimmer">
          <div class="mm-footer-logo">🎯</div>
          <div class="mm-footer-text">Ad Placeholder • Your content here</div>
        </div>
      `;
      
      // Add click handler
      const footerContent = footerAd.querySelector('.mm-footer-content');
      if (footerContent) {
        footerContent.addEventListener('click', () => {
          openAdWindow();
        });
      }
      
      document.body.appendChild(footerAd);
      
      // Adjust body padding to prevent content overlap
      try {
        const h = footerAd.getBoundingClientRect().height || 80;
        const currentPadding = safeParseInt(getComputedStyle(document.body).paddingBottom);
        document.body.style.paddingBottom = Math.max(currentPadding, Math.ceil(h + 10)) + 'px';
      } catch (error) {
        console.warn('[ManaAds] Failed to adjust body padding:', error);
      }
      
      console.log('[ManaAds] Footer ad created');
      
    } catch (error) {
      console.error('[ManaAds] Failed to create footer ad:', error);
    }
  }

  /**
   * Create popup ad
   */
  function createPopupAd() {
    try {
      // Check if already closed this session
      if (getSessionItem(CONFIG.SESSION_KEYS.AD_CLOSED) === '1') {
        console.log('[ManaAds] Popup ad already closed this session');
        return;
      }
      
      // Check if already exists
      if (document.getElementById('mm-ad-popup')) {
        console.log('[ManaAds] Popup ad already exists');
        return;
      }
      
      const popupAd = document.createElement('div');
      popupAd.id = 'mm-ad-popup';
      popupAd.className = 'mm-ad-popup';
      popupAd.innerHTML = `
        <div class="mm-ad-header">
          <div class="mm-ad-title">
            Sponsored
            <span class="mm-ad-badge">AD</span>
          </div>
          <button class="mm-ad-close" aria-label="Close">✕</button>
        </div>
        <div class="mm-ad-body">
          <div class="mm-ad-thumb mm-shimmer">🎁</div>
          <div class="mm-ad-text">Promote your brand here with a non-intrusive popup. Click to learn more.</div>
        </div>
      `;
      
      // Add close button handler
      const closeBtn = popupAd.querySelector('.mm-ad-close');
      if (closeBtn) {
        closeBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          closePopupAd(popupAd);
        });
      }
      
      // Add body click handler
      const adBody = popupAd.querySelector('.mm-ad-body');
      if (adBody) {
        adBody.addEventListener('click', () => {
          openAdWindow();
          closePopupAd(popupAd);
        });
      }
      
      document.body.appendChild(popupAd);
      
      // Show with animation
      requestAnimationFrame(() => {
        popupAd.style.display = 'block';
      });
      
      console.log('[ManaAds] Popup ad created');
      
    } catch (error) {
      console.error('[ManaAds] Failed to create popup ad:', error);
    }
  }

  /**
   * Close popup ad with animation
   */
  function closePopupAd(popupElement) {
    try {
      setSessionItem(CONFIG.SESSION_KEYS.AD_CLOSED, '1');
      
      popupElement.classList.add('mm-closing');
      
      setTimeout(() => {
        if (popupElement.parentNode) {
          popupElement.remove();
        }
      }, 200);
      
      console.log('[ManaAds] Popup ad closed');
      
    } catch (error) {
      console.error('[ManaAds] Failed to close popup ad:', error);
      // Fallback: just remove it
      if (popupElement && popupElement.parentNode) {
        popupElement.remove();
      }
    }
  }

  // =========== AD TRIGGERING ===========
  
  /**
   * Check if click-based ad should be shown
   */
  function shouldShowClickAd(config) {
    try {
      if (!config || !config.enabled) {
        return false;
      }
      
      const threshold = config.clicksThreshold || CONFIG.DEFAULT_CLICKS_THRESHOLD;
      const frequencyMinutes = config.frequency || CONFIG.DEFAULT_FREQUENCY;
      
      // Increment click count
      const clicks = safeParseInt(getSessionItem(CONFIG.SESSION_KEYS.CLICKS), 0) + 1;
      setSessionItem(CONFIG.SESSION_KEYS.CLICKS, String(clicks));
      
      // Check time since last ad
      const lastAdTimestamp = safeParseInt(getSessionItem(CONFIG.SESSION_KEYS.LAST_AD_TS), 0);
      const timeSinceLastAd = Date.now() - lastAdTimestamp;
      const enoughTimePassed = timeSinceLastAd > (frequencyMinutes * 60 * 1000);
      
      // Check if threshold reached
      const thresholdReached = (clicks % threshold) === 0;
      
      if (thresholdReached && enoughTimePassed) {
        setSessionItem(CONFIG.SESSION_KEYS.LAST_AD_TS, String(Date.now()));
        console.log('[ManaAds] Click ad triggered (clicks:', clicks, 'threshold:', threshold, ')');
        return true;
      }
      
      return false;
      
    } catch (error) {
      console.error('[ManaAds] Error checking click ad trigger:', error);
      return false;
    }
  }

  /**
   * Open ad window
   */
  function openAdWindow(url = '/ad.html') {
    try {
      const adWindow = window.open(url, '_blank', 'noopener,noreferrer');
      
      if (!adWindow) {
        console.warn('[ManaAds] Popup blocked, showing inline ad');
        createPopupAd();
      } else {
        console.log('[ManaAds] Ad window opened');
      }
      
    } catch (error) {
      console.error('[ManaAds] Failed to open ad window:', error);
      createPopupAd();
    }
  }

  // =========== INITIALIZATION ===========
  
  /**
   * Initialize ad system
   */
  async function init() {
    try {
      // Check if already initialized
      if (initializationComplete) {
        console.log('[ManaAds] Already initialized');
        return;
      }
      
      console.log('[ManaAds] Initializing...');
      
      // Check ad-free mode
      if (isAdFreeEnabled()) {
        console.log('[ManaAds] Ad-free mode enabled, skipping initialization');
        return;
      }
      
      // Get configuration
      const config = await getConfig();
      
      if (!config || !config.enabled) {
        console.log('[ManaAds] Ads disabled in config');
        return;
      }
      
      // Inject styles
      injectCSS();
      
      // Create footer ad
      createFooterAd();
      
      // Create popup ad after delay
      setTimeout(() => {
        createPopupAd();
      }, CONFIG.POPUP_DELAY);
      
      initializationComplete = true;
      console.log('[ManaAds] Initialization complete');
      
    } catch (error) {
      console.error('[ManaAds] Initialization failed:', error);
    }
  }

  // =========== DOM READY ===========
  
  /**
   * Start initialization when DOM is ready
   */
  function start() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', init);
    } else {
      // DOM already loaded
      init();
    }
  }

  // Start the ad system
  start();

  // =========== PUBLIC API ===========
  
  /**
   * Expose public API
   */
  window.ManaAds = {
    /**
     * Get current ad configuration
     */
    getConfig: async () => {
      try {
        return await getConfig();
      } catch (error) {
        console.error('[ManaAds] getConfig failed:', error);
        return null;
      }
    },
    
    /**
     * Check if click ad should be shown
     */
    shouldOpenOnClick: async () => {
      try {
        const config = await getConfig();
        return shouldShowClickAd(config);
      } catch (error) {
        console.error('[ManaAds] shouldOpenOnClick failed:', error);
        return false;
      }
    },
    
    /**
     * Trigger click-based ad
     */
    triggerClickAd: async () => {
      try {
        const config = await getConfig();
        if (shouldShowClickAd(config)) {
          openAdWindow();
        }
      } catch (error) {
        console.error('[ManaAds] triggerClickAd failed:', error);
      }
    },
    
    /**
     * Manually open ad window
     */
    openAdWindow: (url) => {
      try {
        openAdWindow(url);
      } catch (error) {
        console.error('[ManaAds] openAdWindow failed:', error);
      }
    },
    
    /**
     * Manually show popup ad
     */
    showPopup: () => {
      try {
        createPopupAd();
      } catch (error) {
        console.error('[ManaAds] showPopup failed:', error);
      }
    },
    
    /**
     * Get initialization status
     */
    isInitialized: () => initializationComplete,
    
    /**
     * Reinitialize ad system
     */
    reinit: async () => {
      try {
        initializationComplete = false;
        cachedConfig = null;
        lastConfigFetch = 0;
        await init();
      } catch (error) {
        console.error('[ManaAds] reinit failed:', error);
      }
    }
  };

  console.log('[ManaAds] Script loaded');

})();
