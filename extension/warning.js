(function () {
  
  const params     = new URLSearchParams(window.location.search);
  const blockedUrl = decodeURIComponent(params.get("url") || "");

  
  const urlEl = document.getElementById("blocked-url");
  if (urlEl) urlEl.textContent = blockedUrl || "Unknown URL";

 
  chrome.storage.local.get(["blocked_site_data"], (result) => {
    const data       = result.blocked_site_data || {};
    const confidence = typeof data.confidence === "number" ? data.confidence : 0.85;
    const pct        = Math.round(confidence * 100);

    // Confidence value
    const confValueEl = document.getElementById("confidence-value");
    const confPctEl   = document.getElementById("conf-pct");
    const confBarEl   = document.getElementById("conf-bar");

    if (confValueEl) confValueEl.textContent = `${pct}%`;
    if (confPctEl)   confPctEl.textContent   = `${pct}%`;

    
    setTimeout(() => {
      if (confBarEl) confBarEl.style.width = `${pct}%`;
    }, 300);

    
    const riskEl = document.getElementById("risk-level");
    if (riskEl) {
      if (pct >= 80)      riskEl.textContent = "HIGH";
      else if (pct >= 50) riskEl.textContent = "MEDIUM";
      else                riskEl.textContent = "LOW";
    }

    
    const reasonsList = document.getElementById("reasons-list");
    if (reasonsList) {
      const reasons =
        Array.isArray(data.reasons) && data.reasons.length > 0
          ? data.reasons
          : ["Suspicious URL pattern detected by AI model"];

      reasonsList.innerHTML = reasons
        .map((r) => `<li>${escapeHtml(r)}</li>`)
        .join("");
    }
  });

  // ── Go Back button ────────────────────────────────────────────────────────────
  document.getElementById("go-back-btn")?.addEventListener("click", () => {
    // DO NOT use history.back() — it navigates back to the phishing site,
    // which triggers another scan → redirect loop.
    // Tell background to navigate this tab to a safe new tab page.
    chrome.runtime.sendMessage({ action: "goHome" });
  });

  // ── Proceed Anyway button ─────────────────────────────────────────────────────
  document.getElementById("proceed-btn")?.addEventListener("click", () => {
    if (!blockedUrl) return;

    const confirmed = window.confirm(
      "⚠ DANGER — Phishing Site\n\n" +
      "This website has been flagged as a phishing site by our AI model.\n\n" +
      "Proceeding may expose your passwords, credit card details, and " +
      "personal information to attackers.\n\n" +
      "Are you absolutely sure you want to continue?"
    );

    if (confirmed) {
      // Tell background to allow this URL once, then navigate
      chrome.runtime.sendMessage({ action: "proceedAnyway", url: blockedUrl });
    }
  });

  // ── Helpers ───────────────────────────────────────────────────────────────────
  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
})();
