const API_BASE     = "http://127.0.0.1:5000";
const PREDICT_URL  = `${API_BASE}/predict`;
const REPORT_URL   = `${API_BASE}/report`;
const WARNING_PAGE = chrome.runtime.getURL("warning.html");
const MAX_HISTORY  = 10;


const allowedOnce = new Set();

const ICON_PATHS = {
  safe: {
    16:  "icons/icon16_safe.png",
    32:  "icons/icon32_safe.png",
    48:  "icons/icon48_safe.png",
    128: "icons/icon128_safe.png",
  },
  phishing: {
    16:  "icons/icon16_phishing.png",
    32:  "icons/icon32_phishing.png",
    48:  "icons/icon48_phishing.png",
    128: "icons/icon128_phishing.png",
  },
  unknown: {
    16:  "icons/icon16_unknown.png",
    32:  "icons/icon32_unknown.png",
    48:  "icons/icon48_unknown.png",
    128: "icons/icon128_unknown.png",
  },
};


function saveTabResult(tabId, payload) {
  chrome.storage.local.set({ [`tab_${tabId}`]: payload });
}

function pushHistory(entry) {
  chrome.storage.local.get(["scan_history"], (result) => {
    const current = Array.isArray(result.scan_history) ? result.scan_history : [];
    const next    = [entry, ...current].slice(0, MAX_HISTORY);
    chrome.storage.local.set({ scan_history: next });
  });
}

function incrementScanCount() {
  chrome.storage.local.get(["total_scans"], (result) => {
    chrome.storage.local.set({ total_scans: (result.total_scans || 0) + 1 });
  });
}


function setActionIcon(tabId, state) {
  const path = ICON_PATHS[state] || ICON_PATHS.unknown;
  chrome.action.setIcon({ tabId, path });
}

function setBadge(tabId, state) {
  if (state === "phishing") {
    chrome.action.setBadgeText({ tabId, text: "RISK" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" });
  } else if (state === "safe") {
    chrome.action.setBadgeText({ tabId, text: "SAFE" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#22c55e" });
  } else {
    chrome.action.setBadgeText({ tabId, text: "?" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#f59e0b" });
  }
}


function getRiskLevel(confidence, label) {
  if (label === "legitimate") return "Low Risk";
  if (confidence >= 0.80) return "High Risk";
  if (confidence >= 0.50) return "Medium Risk";
  return "Low Risk";
}


async function scanUrl(tabId, url) {

  if (
    !url ||
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:") ||
    url.startsWith("data:") ||
    url === "about:blank" ||
    url === "about:newtab"
  ) return;


  if (url.startsWith(WARNING_PAGE)) return;


  if (allowedOnce.has(url)) {
    allowedOnce.delete(url);
    return;
  }

  let payload;

  try {
    const response = await fetch(PREDICT_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url }),
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const data      = await response.json();
    const label     = data.label || "unknown";
    const conf      = typeof data.confidence === "number" ? data.confidence : null;
    const reasons   = Array.isArray(data.reasons) ? data.reasons : [];
    const riskLevel = getRiskLevel(conf || 0, label);

    payload = { label, prediction: data.prediction, confidence: conf, reasons, riskLevel, url, checkedAt: Date.now() };

    saveTabResult(tabId, payload);
    pushHistory(payload);
    incrementScanCount();

    if (label === "phishing") {
      
      chrome.storage.local.set({ blocked_site_data: payload });

      setActionIcon(tabId, "phishing");
      setBadge(tabId, "phishing");
      chrome.action.setTitle({
        tabId,
        title: `⚠ Phishing Detected — ${Math.round((conf || 0) * 100)}% confidence`,
      });

      
      chrome.notifications.create(`phishing_${tabId}_${Date.now()}`, {
        type:     "basic",
        iconUrl:  "icons/icon48_phishing.png",
        title:    "⚠ Phishing Website Blocked",
        message:  `CyberShield blocked: ${url.slice(0, 100)}`,
        priority: 2,
      });

      
      const warningUrl = `${WARNING_PAGE}?url=${encodeURIComponent(url)}`;
      chrome.tabs.update(tabId, { url: warningUrl });

    } else {
      
      setActionIcon(tabId, "safe");
      setBadge(tabId, "safe");
      chrome.action.setTitle({ tabId, title: "CyberShield: Site appears safe." });
    }

  } catch (err) {
    
    payload = {
      label: "unknown", prediction: null, confidence: null,
      reasons: [], riskLevel: "Unknown", url,
      checkedAt: Date.now(), error: err.message,
    };
    saveTabResult(tabId, payload);
    pushHistory(payload);

    setActionIcon(tabId, "unknown");
    setBadge(tabId, "unknown");
    chrome.action.setTitle({ tabId, title: "CyberShield: Backend offline or scan failed." });
    console.debug("[CyberShield] Scan failed:", err.message);
  }
}


chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    scanUrl(tabId, tab.url);
  }
});



chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  
  if (message.action === "rescan" && message.url) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) scanUrl(tabs[0].id, message.url);
    });
    sendResponse({ ok: true });
    return true;
  }

  
  if (message.action === "proceedAnyway" && message.url) {
    allowedOnce.add(message.url);
    
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId) {
      chrome.tabs.update(tabId, { url: message.url });
    } else {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) chrome.tabs.update(tabs[0].id, { url: message.url });
      });
    }
    sendResponse({ ok: true });
    return true;
  }

  
  if (message.action === "goHome") {
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId) {
      
      chrome.tabs.create({ url: "about:blank" }, () => {
        chrome.tabs.remove(tabId);
      });
    } else {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.create({ url: "about:blank" }, () => {
            chrome.tabs.remove(tabs[0].id);
          });
        }
      });
    }
    sendResponse({ ok: true });
    return true;
  }

  
  if (message.action === "closeTab") {
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId) {
      chrome.tabs.remove(tabId);
    } else {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) chrome.tabs.remove(tabs[0].id);
      });
    }
    sendResponse({ ok: true });
    return true;
  }

  
  if (message.action === "reportUrl" && message.url) {
    fetch(REPORT_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({
        url:        message.url,
        label:      message.label      || "unknown",
        confidence: message.confidence || null,
        reasons:    message.reasons    || [],
      }),
    })
      .then((r) => r.json())
      .then((data) => sendResponse({ ok: true, data }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true; 
  }
});
