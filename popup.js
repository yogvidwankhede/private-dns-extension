// Enhanced Popup Script for DNS Extension

let isEnabled = true;
let currentStats = null;
let isPremium = false;

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
  console.log('Extension loaded!');
  initializeTabs();
  initializeToggles();
  loadInitialStats();
  generateChartBars();
  checkPremiumStatus();
  setTimeout(addLicenseKeyButton, 500);
});

// Tab switching
function initializeTabs() {
  const tabs = document.querySelectorAll('.tab');
  const contents = document.querySelectorAll('.tab-content');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      contents.forEach(c => c.classList.remove('active'));

      tab.classList.add('active');
      const tabName = tab.getAttribute('data-tab');
      document.getElementById(tabName).classList.add('active');

      if (tabName === 'stats') {
        updateDetailedStats();
      }
    });
  });
}

// Initialize all toggles and switches
function initializeToggles() {
  console.log('Initializing toggles...');

  // Main toggle - with retry
  setTimeout(() => {
    const mainToggle = document.getElementById('main-toggle');
    console.log('Main toggle found:', mainToggle);

    if (mainToggle) {
      const newToggle = mainToggle.cloneNode(true);
      mainToggle.parentNode.replaceChild(newToggle, mainToggle);

      newToggle.addEventListener('click', (e) => {
        console.log('Main toggle clicked!');
        e.stopPropagation();
        isEnabled = !isEnabled;
        newToggle.classList.toggle('active');
        updateStatusBanner();
        console.log('Protection enabled:', isEnabled);
      });
    } else {
      console.error('Main toggle not found!');
    }
  }, 100);

  // Setting switches
  const switches = document.querySelectorAll('.switch');
  console.log('Found switches:', switches.length);

  switches.forEach(sw => {
    const newSwitch = sw.cloneNode(true);
    sw.parentNode.replaceChild(newSwitch, sw);

    newSwitch.addEventListener('click', (e) => {
      e.stopPropagation();
      newSwitch.classList.toggle('active');
      const setting = newSwitch.getAttribute('data-setting');
      const isActive = newSwitch.classList.contains('active');
      saveSetting(setting, isActive);

      console.log(`Toggle ${setting}:`, isActive);
    });
  });
}

// Update status banner
function updateStatusBanner() {
  const banner = document.getElementById('status-banner');
  const icon = banner.querySelector('.status-icon');
  const text = banner.querySelector('.status-text');

  if (isEnabled) {
    banner.classList.remove('disabled');
    icon.textContent = '✓';
    text.textContent = 'Protected & Active';
  } else {
    banner.classList.add('disabled');
    icon.textContent = '✗';
    text.textContent = 'Protection Disabled';
  }
}

// Load initial stats
function loadInitialStats() {
  chrome.runtime.sendMessage({ action: 'getStats' }, (response) => {
    if (response && response.stats) {
      currentStats = response.stats;
      updateStatsDisplay(response.stats);
    }
  });
}

// Update stats display
function updateStatsDisplay(stats) {
  document.getElementById('queries').textContent = formatNumber(stats.queries || 0);
  document.getElementById('blocked').textContent = formatNumber(stats.blocked || 0);
  document.getElementById('cache-hit').textContent =
    (stats.cacheHit ? stats.cacheHit.toFixed(1) + '%' : '0%');

  const cacheHit = stats.cacheHit || 0;
  let speed = 'Slow';
  if (cacheHit > 80) speed = 'Ultra Fast';
  else if (cacheHit > 50) speed = 'Fast';
  else if (cacheHit > 20) speed = 'Good';

  document.getElementById('speed').textContent = speed;
}

// Update detailed stats
function updateDetailedStats() {
  chrome.runtime.sendMessage({ action: 'refreshStats' }, (response) => {
    if (response && response.stats) {
      const stats = response.stats;

      document.getElementById('uptime').textContent = formatUptime(stats.uptime || 0);
      document.getElementById('cache-size').textContent = formatNumber(stats.cacheSize || 0);
      document.getElementById('errors').textContent = stats.errors || 0;
      document.getElementById('rate-limited').textContent = stats.rateLimited || 0;
    }
  });
}

// Format numbers with K, M suffixes
function formatNumber(num) {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
  return num.toString();
}

// Format uptime
function formatUptime(seconds) {
  const hours = Math.floor(seconds / 3600);
  const days = Math.floor(hours / 24);

  if (days > 0) return days + 'd';
  if (hours > 0) return hours + 'h';
  return Math.floor(seconds / 60) + 'm';
}

// Generate chart bars
function generateChartBars() {
  const container = document.getElementById('chart-bars');
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const values = [65, 78, 90, 81, 95, 88, 72];

  container.innerHTML = '';

  values.forEach((value, index) => {
    const bar = document.createElement('div');
    bar.className = 'chart-bar';
    bar.style.height = value + '%';
    bar.innerHTML = `<div class="chart-label">${days[index]}</div>`;
    container.appendChild(bar);
  });
}

// Refresh button
document.getElementById('refresh').addEventListener('click', () => {
  const btn = document.getElementById('refresh');
  const text = document.getElementById('refresh-text');

  btn.disabled = true;
  text.innerHTML = '<span class="loading"></span> Loading...';

  chrome.runtime.sendMessage({ action: 'refreshStats' }, (response) => {
    if (response && response.stats) {
      currentStats = response.stats;
      updateStatsDisplay(response.stats);

      text.textContent = '✓ Updated!';

      setTimeout(() => {
        text.textContent = 'Refresh Stats';
        btn.disabled = false;
      }, 1000);
    } else {
      text.textContent = '✗ Failed';
      setTimeout(() => {
        text.textContent = 'Refresh Stats';
        btn.disabled = false;
      }, 2000);
    }
  });
});

// Test DNS button
document.getElementById('test-dns').addEventListener('click', () => {
  const btn = document.getElementById('test-dns');
  const originalText = btn.innerHTML;

  btn.disabled = true;
  btn.innerHTML = '<span class="loading"></span> Testing...';

  fetch('http://129.154.249.32:9053/')
    .then(r => r.json())
    .then(() => {
      btn.innerHTML = '<span>✓</span><span>Connected!</span>';
      setTimeout(() => {
        btn.innerHTML = originalText;
        btn.disabled = false;
      }, 2000);
    })
    .catch(() => {
      btn.innerHTML = '<span>✗</span><span>Connection Failed</span>';
      setTimeout(() => {
        btn.innerHTML = originalText;
        btn.disabled = false;
      }, 2000);
    });
});

// Export settings
document.getElementById('export-settings').addEventListener('click', () => {
  chrome.storage.local.get(null, (items) => {
    const dataStr = JSON.stringify(items, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);

    const a = document.createElement('a');
    a.href = url;
    a.download = 'dns-settings.json';
    a.click();

    alert('Settings exported successfully!');
  });
});

// Clear cache
document.getElementById('clear-cache').addEventListener('click', () => {
  if (confirm('Are you sure you want to clear the cache?')) {
    chrome.runtime.sendMessage({ action: 'clearCache' }, () => {
      alert('Cache cleared successfully!');
      loadInitialStats();
    });
  }
});

// Help link
document.getElementById('help').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.tabs.create({
    url: 'http://129.154.249.32:9053/'
  });
});

// About link
document.getElementById('about').addEventListener('click', (e) => {
  e.preventDefault();
  alert('Private DNS Extension v1.0.0\n\nBuilt with ❤️\nPowered by your own DNS server!');
});

// Save setting
function saveSetting(key, value) {
  chrome.storage.local.set({ [key]: value }, () => {
    console.log(`Setting ${key} saved:`, value);
  });
}

// Auto-refresh stats every 30 seconds
setInterval(() => {
  if (document.getElementById('overview').classList.contains('active')) {
    chrome.runtime.sendMessage({ action: 'getStats' }, (response) => {
      if (response && response.stats) {
        updateStatsDisplay(response.stats);
      }
    });
  }
}, 30000);

// ============================================
// DEVICE FINGERPRINTING FOR DEMO TRACKING
// ============================================

// Generate unique device fingerprint
async function getDeviceFingerprint() {
  try {
    // Combine multiple browser properties to create unique ID
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Browser fingerprint', 2, 2);

    const canvasData = canvas.toDataURL();
    const userAgent = navigator.userAgent;
    const language = navigator.language;
    const platform = navigator.platform;
    const screenResolution = `${screen.width}x${screen.height}`;
    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;

    const combined = `${canvasData}${userAgent}${language}${platform}${screenResolution}${timezone}`;

    // Create hash
    const encoder = new TextEncoder();
    const data = encoder.encode(combined);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    console.log('Device fingerprint generated:', hashHex.substring(0, 16) + '...');
    return hashHex;
  } catch (error) {
    console.error('Fingerprint generation error:', error);
    // Fallback to random ID if fingerprinting fails
    return 'fallback-' + Math.random().toString(36).substring(2, 15);
  }
}

// ============================================
// PREMIUM FEATURES WITH LICENSE KEY SYSTEM
// ============================================

// Check premium status on load
function checkPremiumStatus() {
  chrome.storage.local.get(['premium', 'licenseKey', 'activatedDate'], (result) => {
    isPremium = result.premium || false;

    if (isPremium) {
      console.log('Premium active! Key:', result.licenseKey);
      console.log('Activated:', result.activatedDate);
    }

    updatePremiumUI();
  });
}

// Update premium UI
function updatePremiumUI() {
  const premiumBanner = document.getElementById('premium-banner');
  const premiumFeatures = document.querySelectorAll('.premium-feature');

  if (isPremium) {
    if (premiumBanner) {
      premiumBanner.classList.add('hidden');
    }

    premiumFeatures.forEach(feature => {
      feature.classList.remove('premium-feature');
      feature.style.opacity = '1';

      const lock = feature.querySelector('.premium-lock');
      if (lock) {
        const featureName = feature.querySelector('h3').textContent.toLowerCase().replace(/\s+/g, '-');
        lock.outerHTML = `
          <div class="switch active" data-setting="${featureName}">
            <div class="switch-slider"></div>
          </div>
        `;
      }
    });

    initializeToggles();
    unlockAllThemes();
  } else {
    if (premiumBanner) {
      premiumBanner.classList.remove('hidden');
    }
  }
}

// Upgrade button
document.getElementById('upgrade-btn').addEventListener('click', () => {
  showUpgradeModal();
});

// Try Demo button (NEW)
document.getElementById('try-demo-btn')?.addEventListener('click', () => {
  showLicenseKeyPrompt();
});

// Show upgrade modal with license key option
function showUpgradeModal() {
  const choice = confirm(
    '🎉 Upgrade to Premium!\n\n' +
    '✔ 10+ Beautiful Themes\n' +
    '✔ DNSSEC Security\n' +
    '✔ Family Safe Mode\n' +
    '✔ Advanced Analytics\n' +
    '✔ Custom DNS Rules\n' +
    '✔ Cloud Sync\n\n' +
    'Only $2.99/month or $24.99/year\n\n' +
    '🎁 Try demo first? Use code: DEMO-2025-TRIAL\n\n' +
    'Click OK to purchase\n' +
    'Click Cancel to try demo'
  );

  if (choice) {
    chrome.tabs.create({
      url: 'http://yogvidwankhede.duckdns.org:4000/purchase.html'
    });
  } else {
    showLicenseKeyPrompt();
  }
}

// License key prompt
function showLicenseKeyPrompt() {
  const key = prompt(
    '🔑 Enter Your License Key:\n\n' +
    'If you purchased Premium, enter your license key below.\n\n' +
    '🎁 First time user? Try our free demo:\n' +
    '   DEMO-2025-TRIAL\n' +
    '   (one-time per device)\n\n' +
    '💎 Purchase Premium: $2.99/month'
  );

  if (key) {
    validateLicenseKey(key);
  }
}

// Validate license key
async function validateLicenseKey(key) {
  console.log('Validating key:', key);

  // Special keys for testing/review
  const testKeys = [
    'DEMO-2025-TRIAL',      // Public demo (one-time)
    'TEST-INTERNAL-DEV',    // For Chrome Web Store reviewers (unlimited)
    'REVIEWER-ACCESS-KEY'   // Alternative reviewer key
  ];

  // Check if it's a test/demo key
  if (testKeys.includes(key.toUpperCase())) {
    // For public demo, check server
    if (key.toUpperCase() === 'DEMO-2025-TRIAL') {
      const fingerprint = await getDeviceFingerprint();

      console.log('Checking demo eligibility...');

      try {
        const response = await fetch('http://yogvidwankhede.duckdns.org:4000/validate-demo', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ fingerprint: fingerprint })
        });

        const data = await response.json();

        if (data.allowed) {
          activatePremiumWithKey('DEMO-2025-TRIAL');
          alert(
            '✅ Demo Activated!\n\n' +
            'You can now try all Premium features!\n\n' +
            '⚠️ This is a ONE-TIME demo per device.\n' +
            'Purchase Premium to keep these features forever!\n\n' +
            '💎 Only $2.99/month or $24.99/year'
          );
        } else {
          alert(
            '❌ Demo Already Used!\n\n' +
            'You have already used your free demo on this device.\n' +
            (data.usedDate ? 'Demo was activated on: ' + new Date(data.usedDate).toLocaleDateString() + '\n\n' : '\n') +
            '💎 Upgrade to Premium:\n' +
            '   • $2.99/month\n' +
            '   • $24.99/year (save 30%)\n\n' +
            'Click "Upgrade to Premium" button to purchase!'
          );
        }
      } catch (error) {
        console.error('Demo validation error:', error);
        alert('❌ Connection error. Please check your internet connection and try again.');
      }
      return;
    }

    // For reviewer/test keys, activate immediately without server check
    if (key.toUpperCase() === 'TEST-INTERNAL-DEV' || key.toUpperCase() === 'REVIEWER-ACCESS-KEY') {
      activatePremiumWithKey(key.toUpperCase());
      alert(
        '✅ Test Access Activated!\n\n' +
        'All Premium features are now unlocked for testing.\n\n' +
        'This is a special reviewer key with unlimited uses.'
      );
      return;
    }
  }

  // For purchased keys, validate with server
  validateWithServer(key);
}

// Validate purchased keys with server
// Validate license key
async function validateLicenseKey(key) {
  console.log('Validating key:', key);

  // Check if it's the demo key
  if (key.toUpperCase() === 'DEMO-2025-TRIAL') {
    const fingerprint = await getDeviceFingerprint();

    console.log('Checking demo eligibility...');

    // Check with server if this device can use demo
    try {
      const response = await fetch('http://yogvidwankhede.duckdns.org:4000/validate-demo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fingerprint: fingerprint })
      });

      const data = await response.json();

      if (data.allowed) {
        // First time using demo - activate it
        activatePremiumWithKey('DEMO-2025-TRIAL');
        alert(
          '✅ Demo Activated!\n\n' +
          'You can now try all Premium features!\n\n' +
          '⚠️ This is a ONE-TIME demo per device.\n' +
          'Purchase Premium to keep these features forever!\n\n' +
          '💎 Only $2.99/month or $24.99/year'
        );
      } else {
        // Already used demo
        alert(
          '❌ Demo Already Used!\n\n' +
          'You have already used your free demo on this device.\n' +
          (data.usedDate ? 'Demo was activated on: ' + new Date(data.usedDate).toLocaleDateString() + '\n\n' : '\n') +
          '💎 Upgrade to Premium:\n' +
          '   • $2.99/month\n' +
          '   • $24.99/year (save 30%)\n\n' +
          'Click "Upgrade to Premium" button to purchase!'
        );
      }
    } catch (error) {
      console.error('Demo validation error:', error);
      alert('❌ Connection error. Please check your internet connection and try again.');
    }
    return;
  }

  // For purchased keys, validate with server
  validateWithServer(key);
}

// Validate purchased keys with server
async function validateWithServer(key) {
  try {
    const response = await fetch('http://yogvidwankhede.duckdns.org:4000/validate-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: key })
    });

    const data = await response.json();

    if (data.valid) {
      activatePremiumWithKey(key);
      alert(
        '✅ Premium Activated!\n\n' +
        'Thank you for your purchase!\n' +
        'All features are now unlocked! 🎉\n\n' +
        'License Key: ' + key
      );
    } else {
      alert(
        '❌ Invalid License Key\n\n' +
        'Please check your key and try again.\n\n' +
        '🎁 Want to try first? Use: DEMO-2025-TRIAL\n\n' +
        'Need help? Contact: yogvidwankhede@gmail.com'
      );
    }
  } catch (error) {
    console.error('Validation error:', error);
    alert('❌ Connection error. Please check your internet connection and try again.');
  }
}

// Activate premium with key
function activatePremiumWithKey(key) {
  chrome.storage.local.set({
    premium: true,
    licenseKey: key,
    activatedDate: new Date().toISOString()
  }, () => {
    isPremium = true;
    updatePremiumUI();

    alert(
      '✅ Premium Activated!\n\n' +
      'Thank you for your purchase!\n' +
      'All features are now unlocked! 🎉\n\n' +
      'License Key: ' + key
    );

    setTimeout(() => {
      openThemeModal();
    }, 500);
  });
}

// Add license key button in settings
function addLicenseKeyButton() {
  if (document.getElementById('license-key-btn')) return;

  const settingsTab = document.getElementById('settings');
  if (!settingsTab) return;

  const actions = settingsTab.querySelector('.actions');
  if (!actions) return;

  const btn = document.createElement('button');
  btn.id = 'license-key-btn';
  btn.className = 'btn btn-primary';
  btn.style.marginBottom = '10px';
  btn.innerHTML = '<span>🔑</span><span>Enter License Key</span>';
  btn.addEventListener('click', showLicenseKeyPrompt);

  actions.insertBefore(btn, actions.firstChild);
}

// ============================================
// THEME SYSTEM
// ============================================

const themeModal = document.getElementById('theme-modal');
const closeThemeModal = document.getElementById('close-theme-modal');

// Open theme modal when clicking on theme feature
document.addEventListener('click', (e) => {
  const themeFeature = e.target.closest('[data-premium="true"]');
  if (themeFeature && themeFeature.querySelector('h3') &&
    themeFeature.querySelector('h3').textContent === 'Custom Themes') {
    if (isPremium) {
      openThemeModal();
    } else {
      showUpgradeModal();
    }
  }
});

function openThemeModal() {
  if (themeModal) {
    themeModal.classList.add('active');
  }
}

function closeThemeModalFunc() {
  if (themeModal) {
    themeModal.classList.remove('active');
  }
}

if (closeThemeModal) {
  closeThemeModal.addEventListener('click', closeThemeModalFunc);
}

if (themeModal) {
  themeModal.addEventListener('click', (e) => {
    if (e.target === themeModal) {
      closeThemeModalFunc();
    }
  });
}

// Theme selection
document.querySelectorAll('.theme-card').forEach(card => {
  card.addEventListener('click', () => {
    if (card.classList.contains('locked') && !isPremium) {
      showUpgradeModal();
      return;
    }

    const theme = card.getAttribute('data-theme');
    applyTheme(theme);

    document.querySelectorAll('.theme-card').forEach(c => c.classList.remove('active'));
    card.classList.add('active');

    chrome.storage.local.set({ theme: theme });
  });
});

// Apply theme
function applyTheme(theme) {
  const themeGradients = {
    purple: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    ocean: 'linear-gradient(135deg, #2E3192 0%, #1BFFFF 100%)',
    sunset: 'linear-gradient(135deg, #FF6B6B 0%, #FFE66D 100%)',
    forest: 'linear-gradient(135deg, #134E5E 0%, #71B280 100%)',
    rose: 'linear-gradient(135deg, #F857A6 0%, #FF5858 100%)',
    midnight: 'linear-gradient(135deg, #000000 0%, #434343 100%)',
    candy: 'linear-gradient(135deg, #FF9A9E 0%, #FAD0C4 100%)',
    mint: 'linear-gradient(135deg, #00F260 0%, #0575E6 100%)',
    gold: 'linear-gradient(135deg, #FFD700 0%, #FF8C00 100%)',
    neon: 'linear-gradient(135deg, #FA8BFF 0%, #2BD2FF 50%, #2BFF88 100%)'
  };

  document.body.style.background = themeGradients[theme] || themeGradients.purple;

  const notification = document.createElement('div');
  notification.textContent = '✓ Theme applied!';
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    left: 50%;
    transform: translateX(-50%);
    background: rgba(74, 222, 128, 0.9);
    color: white;
    padding: 10px 20px;
    border-radius: 8px;
    font-size: 14px;
    z-index: 2000;
    animation: fadeIn 0.3s;
  `;
  document.body.appendChild(notification);

  setTimeout(() => {
    notification.remove();
  }, 2000);
}

// Unlock all themes for premium users
function unlockAllThemes() {
  document.querySelectorAll('.theme-card.locked').forEach(card => {
    card.classList.remove('locked');
  });
}

// Load saved theme on startup
chrome.storage.local.get(['theme'], (result) => {
  if (result.theme) {
    applyTheme(result.theme);

    document.querySelectorAll('.theme-card').forEach(card => {
      if (card.getAttribute('data-theme') === result.theme) {
        card.classList.add('active');
      }
    });
  }
});

// Add premium features click handlers
document.querySelectorAll('.premium-feature').forEach(feature => {
  feature.addEventListener('click', () => {
    if (!isPremium) {
      showUpgradeModal();
    }
  });
});