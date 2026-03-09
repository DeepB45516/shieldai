// ShieldAI Background v3.2
var api = (typeof browser !== "undefined") ? browser : chrome;
var IMAGE_EXT = /\.(jpg|jpeg|png|gif|webp|bmp|avif)(\?.*)?$/i;

function getBackendUrl(cb) {
  api.storage.local.get(["backendUrl"], function(d) {
    cb((d.backendUrl || "http://localhost:3000").replace(/\/$/, ""));
  });
}

function postXHR(url, body, timeout, cb) {
  var xhr = new XMLHttpRequest();
  xhr.open("POST", url, true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.timeout = timeout || 15000;
  xhr.onload = function() {
    try { cb(null, JSON.parse(xhr.responseText)); }
    catch(e) { cb("parse error", null); }
  };
  xhr.onerror = function() { cb("network error", null); };
  xhr.ontimeout = function() { cb("timeout", null); };
  xhr.send(JSON.stringify(body));
}

function notify(title, message) {
  try {
    api.notifications.create("sa_" + Date.now(), {
      type: "basic", iconUrl: "icons/icon48.png",
      title: "ShieldAI: " + title,
      message: (message || "").slice(0, 180), priority: 2
    });
  } catch(e) {}
}

function injectBanner(tabId, color, icon, titleText, subText, flagText) {
  // Sanitize — no quotes or backslashes in injected strings
  function clean(s) { return (s||"").replace(/['"\\`]/g, " ").slice(0, 150); }
  titleText = clean(titleText);
  subText   = clean(subText);
  flagText  = clean(flagText);

  var code = "(function(){" +
    "if(document.getElementById('shieldai-banner'))return;" +
    "var b=document.createElement('div');" +
    "b.id='shieldai-banner';" +
    "b.style.cssText='position:fixed!important;top:0!important;left:0!important;" +
      "right:0!important;z-index:2147483647!important;" +
      "background:linear-gradient(135deg,#050810,#0d1220)!important;" +
      "border-bottom:3px solid " + color + "!important;" +
      "padding:11px 16px!important;font-family:monospace!important;" +
      "font-size:12px!important;color:white!important;" +
      "display:flex!important;align-items:center!important;" +
      "gap:12px!important;box-shadow:0 4px 20px rgba(0,0,0,.95)!important;';" +
    "b.innerHTML='" + icon + " " +
      "<div style=\"flex:1\">" +
        "<div style=\"color:" + color + ";font-weight:bold;letter-spacing:2px;font-size:12px\">ShieldAI: " + titleText + "</div>" +
        "<div style=\"color:#aaa;font-size:10px;margin-top:3px\">" + subText + "</div>" +
        "<div style=\"color:#666;font-size:9px;margin-top:2px\">" + flagText + "</div>" +
      "</div>" +
      "<button onclick=\"document.getElementById(chr39shieldai-bannerchr39).remove()\" " +
        "style=\"background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2);" +
        "color:white;padding:5px 12px;cursor:pointer;border-radius:3px;font-size:10px\">X</button>';" +
    "b.querySelector('button').onclick=function(){b.remove();};" +
    "var root=document.body||document.documentElement;" +
    "root.insertBefore(b,root.firstChild);" +
  "})()";

  api.tabs.executeScript(tabId, { code: code });
}

// ── SCAN DIRECT IMAGE TAB ───────────────────────────────────────
function scanDirectImageTab(tabId, imageUrl) {
  console.log("[ShieldAI] Direct image tab:", imageUrl.slice(0, 80));

  getBackendUrl(function(base) {
    postXHR(base + "/scan/image", { imageUrl: imageUrl, imageBase64: null }, 30000, function(err, result) {
      if (err || !result) {
        console.warn("[ShieldAI] Image scan failed:", err);
        return;
      }

      console.log("[ShieldAI] Image result: score=" + result.score + " is_ai=" + result.is_ai);

      // Store result for popup
      var obj = {};
      obj["scan_" + tabId] = Object.assign({}, result, { url: imageUrl, scanType: "image", ts: Date.now() });
      api.storage.local.set(obj);

      // Show banner regardless of result — user opened this to test
      var color = result.is_ai ? (result.is_deepfake ? "#ff2d55" : "#ff9f0a") : "#30d158";
      var icon  = result.is_ai ? (result.is_deepfake ? "WARNING" : "AI") : "REAL";
      var titleText = result.is_deepfake ? "DEEPFAKE DETECTED"
                    : result.is_ai       ? "AI-GENERATED IMAGE  Score: " + result.score + "/100"
                    :                      "REAL PHOTO  Score: " + result.score + "/100";
      var gen   = (result.generator && result.generator !== "Unknown" && result.generator !== "Real") ? "Generator: " + result.generator + "  " : "";
      var conf  = result.confidence ? "Confidence: " + result.confidence : "";
      var subText  = (result.verdict || "") + "  " + gen + conf;
      var flagText = (result.flags || []).slice(0, 3).join("  |  ");

      injectBanner(tabId, color, icon, titleText, subText, flagText);

      if (result.is_ai) {
        notify(
          result.is_deepfake ? "DEEPFAKE DETECTED" : "AI IMAGE DETECTED",
          result.verdict + " (score: " + result.score + "/100)"
        );
      }
    });
  });
}

// ── SCAN NORMAL WEBPAGE ─────────────────────────────────────────
function scanWebpage(tabId, url, title) {
  api.tabs.executeScript(tabId, {
    code: "(function(){var m='';var md=document.querySelector(\"meta[name='description']\");if(md)m+=md.getAttribute('content')||'';return(m+' '+(document.body?document.body.innerText:'')).slice(0,2000);})()"
  }, function(results) {
    if (api.runtime.lastError) return;
    var text = (results && results[0]) ? String(results[0]) : "";

    getBackendUrl(function(base) {
      postXHR(base + "/scan/website", { url: url, title: title, bodyText: text }, 15000, function(err, r) {
        if (err || !r) return;
        var obj = {};
        obj["scan_" + tabId] = Object.assign({}, r, { url: url, ts: Date.now() });
        api.storage.local.set(obj);

        if (r.score >= 50) {
          var color = r.threatType === "piracy" ? "#ff9f0a" : "#ff2d55";
          var icon  = r.threatType === "piracy" ? "PIRACY" : "PHISHING";
          var flags = (r.flags || []).slice(0, 2).join("  |  ");
          notify((r.threatType || "THREAT").toUpperCase() + " DETECTED", (r.flags||[])[0] || r.verdict || "");
          injectBanner(tabId, color, icon, (r.threatType||"THREAT").toUpperCase() + " Score: " + r.score + "/100", r.verdict || "", flags);
        }
      });
    });
  });
}

// ── TAB LISTENER — detects image tabs vs normal pages ───────────
api.tabs.onUpdated.addListener(function(tabId, info, tab) {
  if (info.status !== "complete") return;
  if (!tab.url || !tab.url.startsWith("http")) return;

  var urlClean = tab.url.split("?")[0].split("#")[0];

  if (IMAGE_EXT.test(urlClean)) {
    // Direct image URL opened in tab — scan for AI generation
    scanDirectImageTab(tabId, tab.url);
  } else {
    // Normal page — scan for phishing/piracy/malware
    scanWebpage(tabId, tab.url, tab.title || "");
  }
});

// ── BLOCK DANGEROUS DOWNLOADS ───────────────────────────────────
api.downloads.onCreated.addListener(function(item) {
  var name = (item.filename || item.url || "").split("/").pop().split("?")[0];
  if (/\.(exe|scr|bat|cmd|ps1|vbs|jar|hta|msi|reg|dll)$/i.test(name)) {
    api.downloads.cancel(item.id);
    notify("DOWNLOAD BLOCKED", "Dangerous file: " + name);
    console.log("[ShieldAI] Blocked:", name);
  }
});

// ── MESSAGE HANDLERS ────────────────────────────────────────────
api.runtime.onMessage.addListener(function(msg, sender, sendResponse) {

  // Images on webpages scanned by content.js
  if (msg.type === "IMAGE_AI_SCAN") {
    getBackendUrl(function(base) {
      postXHR(base + "/scan/image", {
        imageUrl: msg.imageUrl,
        imageBase64: msg.imageBase64,
        mediaType: msg.mediaType || "image/jpeg"
      }, 25000, function(err, result) {
        if (err || !result) { sendResponse({ is_ai: false, score: 0 }); return; }
        sendResponse(result);
        if (result.is_ai && result.score >= 50) {
          notify(result.is_deepfake ? "DEEPFAKE ON PAGE" : "AI IMAGE ON PAGE", result.verdict || "");
        }
      });
    });
    return true;
  }

  // Email phishing — relayed from Gmail/Outlook content script
  if (msg.type === "EMAIL_SCAN") {
    getBackendUrl(function(base) {
      postXHR(base + "/scan/email", {
        subject: msg.subject, sender: msg.sender, body: msg.body,url: msg.pageUrl || ""
      }, 15000, function(err, result) {
        if (err || !result) { sendResponse({ threat: false, score: 0, flags: [] }); return; }
        sendResponse(result);
        if (result.threat) notify("PHISHING EMAIL", result.verdict || (result.flags||[])[0] || "");
      });
    });
    return true;
  }

});

console.log("[ShieldAI] background v3.2 ready");
console.log("Email scan URL:", msg.pageUrl);