// ShieldAI Content Script v3
// Handles: email scanning on Gmail/Outlook, banner display
(function () {
  if (window.__shieldai4) return;
  window.__shieldai4 = true;

  var api = (typeof browser !== "undefined") ? browser : chrome;

  // ── Show threat banner (called by background via executeScript) ─
  // Banner is now injected directly by background.js via executeScript
  // This listener is a fallback
  api.runtime.onMessage.addListener(function(msg) {
    if (msg.type === "SHOW_BANNER") {
      showBanner(msg.threatType, msg.flags, msg.score, msg.verdict);
    }
  });

  function showBanner(threatType, flags, score, verdict) {
    var old = document.getElementById("shieldai-b");
    if (old) old.remove();
    var colors = { phishing:"#ff2d55", malcode:"#ff2d55", piracy:"#ff9f0a", suspicious:"#ff9f0a" };
    var icons  = { phishing:"🎣", malcode:"🦠", piracy:"⚓", suspicious:"⚠️" };
    var labels = { phishing:"PHISHING SITE", malcode:"MALICIOUS CODE", piracy:"PIRACY SITE", suspicious:"SUSPICIOUS" };
    var c = colors[threatType] || "#ff9f0a";
    var b = document.createElement("div");
    b.id = "shieldai-b";
    b.setAttribute("style",
      "position:fixed!important;top:0!important;left:0!important;right:0!important;" +
      "z-index:2147483647!important;background:linear-gradient(135deg,#050810,#0d1220)!important;" +
      "border-bottom:3px solid " + c + "!important;padding:10px 16px!important;" +
      "display:flex!important;align-items:center!important;gap:12px!important;" +
      "font-family:monospace!important;font-size:12px!important;" +
      "box-shadow:0 2px 20px rgba(0,0,0,.9)!important;color:white!important;");
    b.innerHTML =
      "<span style='font-size:20px'>" + (icons[threatType]||"⚠️") + "</span>" +
      "<div style='flex:1'>" +
        "<div style='color:" + c + ";font-weight:bold;letter-spacing:2px;font-size:12px'>" +
          "⚡ ShieldAI: " + (labels[threatType]||"THREAT") + " · Score: " + (score||"?") + "/100</div>" +
        "<div style='color:#aaa;font-size:10px;margin-top:2px'>" +
          (verdict ? verdict + " · " : "") + (flags||[]).slice(0,2).join(" | ") + "</div>" +
      "</div>" +
      "<button onclick=\"this.parentElement.remove();document.body.style.paddingTop=''\" " +
        "style='background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2);" +
        "color:white;padding:5px 12px;cursor:pointer;border-radius:3px;font-family:monospace;font-size:10px'>✕</button>";
    document.body.insertBefore(b, document.body.firstChild);
    document.body.style.paddingTop = "52px";
  }


  // ── AI IMAGE DETECTION ────────────────────────────────────────────
  // Scans images on page, converts to base64, sends to backend for AI detection
  var scannedImages = new Set();

  function scanImage(img) {
    var src = img.src || img.currentSrc || "";
    if (!src || !src.startsWith("http")) return;
    if (scannedImages.has(src)) return;
    scannedImages.add(src);

    // Only scan images large enough to be meaningful (skip icons/tiny images)
    var w = img.naturalWidth || img.width || 0;
    var h = img.naturalHeight || img.height || 0;
    if (w < 100 || h < 100) return;

    // Convert image to base64 via canvas
    try {
      var canvas = document.createElement("canvas");
      // Cap at 512px max to keep payload small
      var maxDim = 512;
      var scale = Math.min(maxDim / w, maxDim / h, 1);
      canvas.width = Math.round(w * scale);
      canvas.height = Math.round(h * scale);
      var ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

      // Try to get base64 (may fail for cross-origin images)
      var base64 = canvas.toDataURL("image/jpeg", 0.7);
      var pureBase64 = base64.replace(/^data:image\/[a-z]+;base64,/, "");

      api.runtime.sendMessage({
        type: "IMAGE_AI_SCAN",
        imageUrl: src,
        imageBase64: pureBase64,
        mediaType: "image/jpeg",
        width: w,
        height: h
      }, function(res) {
        if (api.runtime.lastError) return;
        if (!res) return;

        // Mark image visually if AI-generated
        if (res.is_ai && res.score >= 50) {
          var badge = document.createElement("div");
          badge.style.cssText = [
            "position:absolute",
            "top:6px",
            "left:6px",
            "background:" + (res.is_deepfake ? "#ff2d55" : "#ff9f0a"),
            "color:white",
            "font-family:monospace",
            "font-size:10px",
            "font-weight:bold",
            "padding:3px 8px",
            "border-radius:3px",
            "z-index:9999",
            "pointer-events:none",
            "letter-spacing:1px"
          ].join(";");
          badge.textContent = res.is_deepfake ? "⚡ DEEPFAKE" : "🤖 AI GENERATED";
          badge.title = res.verdict + " (" + res.score + "/100) — " + (res.generator || "");

          // Position relative to image
          var parent = img.parentElement;
          if (parent && window.getComputedStyle(parent).position === "static") {
            parent.style.position = "relative";
          }
          if (parent) {
            parent.appendChild(badge);
          }

          // Also add a subtle border
          img.style.outline = "2px solid " + (res.is_deepfake ? "#ff2d55" : "#ff9f0a");
          img.title = "⚡ ShieldAI: " + res.verdict;
        }
      });
    } catch (crossOriginErr) {
      // Canvas blocked due to CORS — send URL only, no base64
      api.runtime.sendMessage({
        type: "IMAGE_AI_SCAN",
        imageUrl: src,
        imageBase64: null,
        mediaType: "image/jpeg",
        width: w,
        height: h
      });
    }
  }

  // Scan images already on page
  function scanAllImages() {
    document.querySelectorAll("img").forEach(function(img) {
      if (img.complete && img.naturalWidth > 0) {
        scanImage(img);
      } else {
        img.addEventListener("load", function() { scanImage(img); }, { once: true });
      }
    });
  }

  // Scan new images added dynamically
  new MutationObserver(function(muts) {
    muts.forEach(function(m) {
      m.addedNodes.forEach(function(n) {
        if (n.tagName === "IMG") {
          if (n.complete) scanImage(n);
          else n.addEventListener("load", function() { scanImage(n); }, { once: true });
        }
        if (n.querySelectorAll) {
          n.querySelectorAll("img").forEach(function(img) {
            if (img.complete) scanImage(img);
            else img.addEventListener("load", function() { scanImage(img); }, { once: true });
          });
        }
      });
    });
  }).observe(document.body, { childList: true, subtree: true });

  // Run after page loads
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", scanAllImages);
  } else {
    setTimeout(scanAllImages, 1000);
  }

  // ── Gmail / Outlook email scanning ────────────────────────────
  var emailHosts = ["mail.google.com","outlook.live.com","outlook.office.com","mail.yahoo.com","mail.proton.me"];
  if (!emailHosts.some(function(h) { return location.hostname.includes(h); })) return;

  new MutationObserver(function(muts) {
    muts.forEach(function(m) {
      m.addedNodes.forEach(function(n) {
        if (n.nodeType !== 1) return;
        // Gmail
        var body = n.querySelector && (n.querySelector(".ii.gt") || n.querySelector(".a3s.aiL"));
        if (body && !body.dataset.shieldScanned) {
          body.dataset.shieldScanned = "1";
          var subject = "";
          var subEl = document.querySelector(".hP");
          if (subEl) subject = subEl.innerText || "";
          var sender = "";
          var sEl = document.querySelector(".gD");
          if (sEl) sender = sEl.getAttribute("email") || sEl.innerText || "";

          api.runtime.sendMessage({
            type: "EMAIL_SCAN",
            subject: subject, sender: sender,
            body: (body.innerText || "").slice(0, 1500),
            pageUrl: location.href
          }, function(res) {
            if (api.runtime.lastError || !res || !res.threat) return;
            injectEmailWarning(body, res);
          });
        }
      });
    });
  }).observe(document.body, { childList: true, subtree: true });

  function injectEmailWarning(el, result) {
    if (el.querySelector(".shieldai-warn")) return;
    var w = document.createElement("div");
    w.className = "shieldai-warn";
    w.style.cssText = "background:#18000a;border:2px solid #ff2d55;border-radius:8px;" +
      "padding:12px 16px;margin:10px 0;font-family:monospace;font-size:12px;color:#ff2d55;";
    w.innerHTML =
      "<strong>⚡ ShieldAI: PHISHING EMAIL — " + (result.score||"?") + "/100</strong><br>" +
      "<span style='color:#ff9f0a;font-size:11px'>" + (result.verdict||"") + "</span><br>" +
      "<div style='margin-top:6px;font-size:10px;color:#888'>" +
        (result.flags||[]).slice(0,3).map(function(f){return "▸ "+f;}).join("<br>") +
      "</div>" +
      "<div style='margin-top:5px;font-size:9px;color:#555'>Do NOT click links or enter credentials</div>";
    el.insertBefore(w, el.firstChild);
  }
})();
