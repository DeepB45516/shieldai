// ShieldAI popup.js - simple and direct
var api = (typeof browser !== "undefined") ? browser : chrome;

var backendUrl = "http://localhost:3000";

// ── LOG ─────────────────────────────────────────────────────────
function log(cls, msg) {
  var el = document.getElementById("log");
  var d = document.createElement("div");
  d.className = cls;
  d.textContent = new Date().toLocaleTimeString() + " " + msg;
  el.appendChild(d);
  el.scrollTop = el.scrollHeight;
  console.log("[ShieldAI]", cls, msg);
}

// ── DOT COLOR ────────────────────────────────────────────────────
function setDot(color) {
  var dot = document.getElementById("dot");
  dot.style.background = color;
  dot.style.boxShadow = "0 0 6px " + color;
}

// ── PING ─────────────────────────────────────────────────────────
function ping() {
  var url = document.getElementById("urlInput").value.trim().replace(/\/$/, "");
  backendUrl = url;
  log("info", "Pinging " + url + "...");
  setDot("#ff9f0a");

  var xhr = new XMLHttpRequest();
  xhr.open("GET", url + "/", true);
  xhr.timeout = 5000;

  xhr.onload = function() {
    log("info", "Raw response: " + xhr.responseText.slice(0, 100));
    try {
      var data = JSON.parse(xhr.responseText);
      log("ok", "Backend ONLINE: " + (data.status || "ok") + " v" + (data.version || "?"));
      setDot("#30d158");
    } catch (e) {
      log("warn", "Got response but not JSON. Status: " + xhr.status);
      setDot("#ff9f0a");
    }
  };

  xhr.onerror = function() {
    log("err", "CANNOT REACH " + url);
    log("err", "→ Make sure node server.js is running in PowerShell");
    log("err", "→ Try: http://localhost:3000 in your browser first");
    setDot("#ff2d55");
  };

  xhr.ontimeout = function() {
    log("err", "Timed out reaching " + url);
    setDot("#ff2d55");
  };

  xhr.send();
}

// ── SCAN ─────────────────────────────────────────────────────────
function scan() {
  var url = document.getElementById("urlInput").value.trim().replace(/\/$/, "");
  backendUrl = url;

  var btn = document.getElementById("scanBtn");
  btn.disabled = true;
  btn.textContent = "SCANNING...";
  log("info", "=== SCAN STARTED ===");

  // Get current tab
  api.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    if (!tabs || !tabs[0]) {
      log("err", "No active tab");
      btn.disabled = false;
      btn.textContent = "▶ SCAN THIS PAGE";
      return;
    }

    var tab = tabs[0];
    var tabUrl = tab.url || "";

    log("info", "Tab URL: " + tabUrl.slice(0, 80));

    if (!tabUrl.startsWith("http")) {
      log("err", "Not an http page. Navigate to a website first.");
      btn.disabled = false;
      btn.textContent = "▶ SCAN THIS PAGE";
      return;
    }

    document.getElementById("scoreUrl").textContent = tabUrl.slice(0, 60);

    // Get page text
    log("info", "Extracting page text...");
    api.tabs.executeScript(tab.id, {
      code: "document.body ? document.body.innerText.slice(0, 2000) : ''"
    }, function(results) {
      var pageText = "";

      if (api.runtime.lastError) {
        log("warn", "Could not extract page text: " + api.runtime.lastError.message);
        log("info", "Continuing with URL-only scan...");
      } else {
        pageText = (results && results[0]) ? String(results[0]) : "";
        log("ok", "Got " + pageText.length + " chars of page text");
      }

      // Call backend
      log("info", "Calling backend: " + backendUrl + "/scan/website");

      var xhr = new XMLHttpRequest();
      xhr.open("POST", backendUrl + "/scan/website", true);
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.timeout = 20000;

      xhr.onload = function() {
        btn.disabled = false;
        btn.textContent = "▶ SCAN THIS PAGE";

        log("info", "Backend status: " + xhr.status);
        log("info", "Raw: " + xhr.responseText.slice(0, 200));

        if (xhr.status !== 200) {
          log("err", "Backend error: HTTP " + xhr.status);
          return;
        }

        try {
          var result = JSON.parse(xhr.responseText);
          log("ok", "Score: " + result.score + " | Type: " + result.threatType);
          log("ok", "Verdict: " + (result.verdict || "none"));
          if (result.flags && result.flags.length) {
            log(result.score >= 50 ? "err" : "warn", "Flags: " + result.flags.slice(0, 3).join(" | "));
          }
          renderResult(result, tabUrl);
        } catch (e) {
          log("err", "JSON parse error: " + e.message);
        }
      };

      xhr.onerror = function() {
        btn.disabled = false;
        btn.textContent = "▶ SCAN THIS PAGE";
        log("err", "Network error reaching backend");
        log("err", "Is server.js still running? Check your PowerShell window.");
      };

      xhr.ontimeout = function() {
        btn.disabled = false;
        btn.textContent = "▶ SCAN THIS PAGE";
        log("err", "Backend timed out (20s). Claude AI may be slow.");
      };

      xhr.send(JSON.stringify({
        url: tabUrl,
        title: tab.title || "",
        bodyText: pageText
      }));
    });
  });
}

// ── RENDER ───────────────────────────────────────────────────────
function renderResult(r, url) {
  var s = r.score || 0;
  var c = s >= 65 ? "#ff2d55" : s >= 35 ? "#ff9f0a" : "#30d158";
  var lbl = s >= 65 ? "DANGER" : s >= 35 ? "SUSPICIOUS" : "SAFE";

  document.getElementById("scoreNum").textContent = s;
  document.getElementById("scoreNum").style.color = c;
  document.getElementById("scoreLabel").textContent = lbl;
  document.getElementById("scoreLabel").style.color = c;
  try { document.getElementById("scoreUrl").textContent = new URL(url).hostname; }
  catch (e) { document.getElementById("scoreUrl").textContent = url.slice(0, 50); }
  document.getElementById("scoreVerdict").textContent = r.verdict || "";
  document.getElementById("scoreVerdict").style.color = c;

  var flagsEl = document.getElementById("flagsDiv");
  flagsEl.innerHTML = "";
  (r.flags || []).slice(0, 4).forEach(function(f) {
    var d = document.createElement("div");
    d.textContent = "▸ " + f;
    d.style.color = s >= 65 ? "#ff2d55" : s >= 35 ? "#ff9f0a" : "#5a6a8a";
    d.style.fontSize = "9px";
    d.style.padding = "1px 0";
    flagsEl.appendChild(d);
  });
}

// ── INIT ─────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", function() {
  log("ok", "popup.js loaded successfully");

  // Load saved URL
  api.storage.local.get(["backendUrl"], function(d) {
    if (d.backendUrl) {
      backendUrl = d.backendUrl;
      document.getElementById("urlInput").value = backendUrl;
      log("ok", "Loaded saved URL: " + backendUrl);
    }
    ping();
  });

  // Wire buttons
  document.getElementById("pingBtn").addEventListener("click", ping);
  document.getElementById("saveBtn").addEventListener("click", function() {
    var val = document.getElementById("urlInput").value.trim().replace(/\/$/, "");
    backendUrl = val;
    api.storage.local.set({ backendUrl: val }, function() {
      log("ok", "Saved: " + val);
    });
  });
  document.getElementById("scanBtn").addEventListener("click", scan);

  log("info", "Ready. Backend: " + backendUrl);
});
