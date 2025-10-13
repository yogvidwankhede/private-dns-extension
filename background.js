// Background service worker for DNS extension

const DNS_SERVER = 'https://yogvidwankhede.duckdns.org/dns-query';

// Initialize stats
let stats = {
  queries: 0,
  blocked: 0,
  cacheHit: 0
};

// Load stats from storage
chrome.storage.local.get(['stats'], (result) => {
  if (result.stats) {
    stats = result.stats;
  }
});

// Save stats periodically
function saveStats() {
  chrome.storage.local.set({ stats: stats });
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getStats') {
    sendResponse({ stats: stats });
  } else if (request.action === 'refreshStats') {
    // Fetch from server metrics
    fetch('http://129.154.249.32:9053/')
      .then(r => r.json())
      .then(data => {
        stats.queries = data.server.queries_total;
        stats.blocked = data.server.blocked_queries;
        stats.cacheHit = parseFloat(data.cache.hit_rate);
        saveStats();
        sendResponse({ stats: stats });
      })
      .catch(err => {
        console.error('Failed to fetch stats:', err);
        sendResponse({ stats: stats });
      });
    return true; // Keep channel open for async response
  }
});

console.log('DNS Extension loaded!');