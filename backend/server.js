// ShieldAI Backend Server
// Deploy free on Render.com or Railway.app
// Or run locally: node server.js
require("dotenv").config();

const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const express = require("express");
const fetch = require("node-fetch");
const cors = require("cors");
const app = express();

app.use(cors());
app.use(express.json({ limit: "2mb" }));

// ── CONFIG ────────────────────────────────────────────────────────
const GOOGLE_SAFE_BROWSING_KEY = process.env.GSB_KEY || "YOUR_GOOGLE_SAFE_BROWSING_KEY";
const VIRUSTOTAL_KEY = process.env.VT_KEY || "YOUR_VIRUSTOTAL_KEY";
const PORT = process.env.PORT || 3000;

// ── OPENROUTER TEXT (Phishing detection) ─────────────────
async function callAIText(prompt) {
  const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
      "Content-Type": "application/json",
      "HTTP-Referer": "http://localhost:3000",
      "X-Title": "ShieldAI"
    },
    body: JSON.stringify({
      model: "openai/gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      max_tokens: 400
    })
  });

  const data = await res.json();

  if (!res.ok) {
    console.error("OpenRouter Text Error:", data);
    throw new Error(data?.error?.message || "AI text error");
  }

  return data.choices[0].message.content;
}
// ── OPENROUTER VISION (FREE) ─────────────────────────────
async function callOpenRouterVision(imageUrl, prompt) {
  const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
      "Content-Type": "application/json",
      "HTTP-Referer": "http://localhost:3000",
      "X-Title": "ShieldAI"
    },
    
    body: JSON.stringify({
      model: "openai/gpt-4o-mini",
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: prompt },
            {
              type: "image_url",
              image_url: { url: imageUrl }
            }
          ]
        }
      ],
      max_tokens: 500
    })
  });

  const data = await res.json();

  if (!res.ok) {
    console.error("OpenRouter error:", data);
    throw new Error(data?.error?.message || "OpenRouter Vision error");
  }

  return data.choices[0].message.content;
}

// ── FETCH IMAGE AS BASE64 ─────────────────────────────────────────
async function fetchImageAsBase64(imageUrl) {
  const res = await fetch(imageUrl);
  if (!res.ok) throw new Error("Cannot fetch image: HTTP " + res.status);
  const contentType = res.headers.get("content-type") || "image/jpeg";
  const arrayBuffer = await res.arrayBuffer();
  const buffer = Buffer.from(arrayBuffer);
  return {
    base64: buffer.toString("base64"),
    mediaType: contentType.split(";")[0].trim(),
    sizeKB: Math.round(buffer.length / 1024)
  };
}

function parseJSON(text) {
  if (!text) return null;
  try { return JSON.parse(text.replace(/```json|```/g, "").trim()); } catch {}
  const m = text.match(/\{[\s\S]*\}/);
  if (m) try { return JSON.parse(m[0]); } catch {}
  return null;
}

// ================================================================
// RULE-BASED DETECTION (always runs, no API needed)
// ================================================================

const PIRACY_DOMAINS = [
  "thepiratebay","piratebay","rarbg","1337x","yify","fmovies","putlocker",
  "soap2day","gomovies","kickasstorrent","torrentz","nyaa","animesuge",
  "tamilrockers","filmyzilla","jiorockers","isaimini","kuttymovies","movierulz",
  "worldfree4u","downloadhub","7starhd","mp4moviez","hdmovie","filmywap",
  "pagalmovies","moviesflix","9xmovie","bollyflix","tamilgun","klwap",
  "steamunlocked","fitgirl-repacks","igg-games","ocean-of-games",
  "skidrowreloaded","skidrowcodex","crackingpatching","getintopc",
  "sci-hub","libgen","bookfi","zlibrary","b-ok","pdfdrive",
  "crackforums","nulled","warez","cracked.to","nsane","team-os",
  "123movies","fmovie","moviesjoy","lookmovie","solarmovie","hdmovie2",
  "streameast","crackstreams","buffstreams","sportsurge","methstreams",
  "torrentgalaxy","limetorrents","zooqle","skytorrents","magnetdl","bitsearch",
  "yggtorrent","cpasbien","torrent9","fztvseries","o2tvseries","extratorrents"
];

const PIRACY_KEYWORDS = [
  "download torrent", "magnet link", "torrent file", "seeders", "leechers",
  "free download full movie", "watch online free hd", "free stream hd",
  "download full album free", "cracked software", "serial key generator",
  "keygen download", "license key free", "activation key free",
  "nulled script", "warez download", "pirated game", "free premium account",
  "cracked apk", "mod apk unlimited", "bypass premium", "scene release",
  "cracked by", "repack by", "fitted by", "compressed by"
];

const PHISHING_BRANDS = [
  "paypal","apple","google","microsoft","amazon","netflix","facebook",
  "instagram","twitter","linkedin","dropbox","adobe","chase","wellsfargo",
  "bankofamerica","citibank","barclays","hsbc","santander","sbi","hdfc","icici",
  "binance","coinbase","metamask","upwork","fiverr"
];

const MALCODE_PATTERNS = [
  { re: /eval\s*\(\s*atob\s*\(/, label: "Base64 eval dropper" },
  { re: /eval\s*\(\s*unescape\s*\(/, label: "Escaped eval payload" },
  { re: /document\.write\s*\(\s*unescape/, label: "Obfuscated document.write" },
  { re: /String\.fromCharCode\((\d+,){8,}/, label: "CharCode obfuscation" },
  { re: /new\s+Function\s*\(\s*["'][^"']{100,}/, label: "Dynamic Function() from string" },
  { re: /coinhive|cryptominer|coin-hive|minero\.cc/, label: "Cryptominer detected" },
  { re: /powershell.{0,30}-e[nc]{0,2}[code]* /, label: "Encoded PowerShell" },
  { re: /fetch\([^)]{0,100}\).*document\.cookie/, label: "Cookie theft via fetch" },
  { re: /(\\x[0-9a-f]{2}){20,}/i, label: "Hex-encoded payload (20+ bytes)" },
  { re: /0x[0-9a-f]{2}(\s*,\s*0x[0-9a-f]{2}){20,}/i, label: "Hex array payload" },
  { re: /window\[['"]eval['"]\]|window\[atob\(/, label: "Evasive eval via window" },
  { re: /navigator\.sendBeacon.{0,60}(cookie|password|token)/, label: "Credential beacon exfiltration" },
  { re: /keyup|keydown.{0,100}(fetch|XMLHttpRequest)/, label: "Keylogger pattern" },
  { re: /WebAssembly\.instantiate.{0,200}fetch/, label: "WASM payload loader" },
  { re: /atob\(atob\(/, label: "Double base64 encoding (deep obfuscation)" },
  { re: /\\u00[0-9a-f]{2}(\\u00[0-9a-f]{2}){10,}/i, label: "Unicode escape obfuscation" }
];

function calcEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((s, f) => { const p = f/len; return s + p * Math.log2(p); }, 0);
}

function rulesPiracy(url, title, bodyText) {
  let score = 0;
  const flags = [];
  const combined = ((title || "") + " " + (bodyText || "")).toLowerCase();

  try {
    const hostname = new URL(url).hostname.toLowerCase().replace(/^www\.|^m\./, "");
    for (const d of PIRACY_DOMAINS) {
      if (hostname === d || hostname.endsWith("." + d) || hostname.startsWith(d + ".")) {
        score += 85; flags.push("Known piracy domain: " + d); break;
      }
    }
    if (/\.(cam|buzz|rest|sbs|vip|live|run|fun|one|club)$/.test(hostname) && score === 0) {
      score += 10; flags.push("Suspicious TLD");
    }
  } catch {}

  for (const kw of PIRACY_KEYWORDS) {
    if (combined.includes(kw)) { score += 15; flags.push(`Keyword: "${kw}"`); }
  }
  if (combined.includes("seeders") && combined.includes("leechers")) {
    score += 40; flags.push("Torrent tracker page");
  }
  if (combined.includes(".torrent") || combined.includes("magnet:?xt=")) {
    score += 50; flags.push("Torrent/magnet links on page");
  }

  return { score: Math.min(score, 100), flags };
}

function rulesPhishing(url, title, bodyText) {
  let score = 0;
  const flags = [];
  const combined = ((title || "") + " " + (bodyText || "")).toLowerCase();

  try {
    const u = new URL(url);
    const domain = u.hostname.toLowerCase().replace(/^www\./, "");

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) { score += 55; flags.push("IP address URL"); }
    if (/\.(xyz|top|click|loan|work|gq|tk|ml|cf|ga|pw|cc)$/.test(domain)) { score += 25; flags.push("High-risk TLD"); }
    if (/[аеіоурсАЕІОУРС]/.test(domain)) { score += 65; flags.push("Homograph/unicode attack in domain"); }
    if (domain.split(".").length > 5) { score += 20; flags.push("Excessive subdomains"); }
    if (/paypa1|pay-pal|paypai|arnazon|amaz0n|g00gle|microsofl|appl3|app1e/.test(domain)) {
      score += 70; flags.push("Typosquatting detected");
    }
    for (const brand of PHISHING_BRANDS) {
      if (domain === brand + ".com" || domain.endsWith("." + brand + ".com") || domain.includes(brand)) {
        const mainDomain = brand + ".com";
    
        // Allow official domain and subdomains
        const isOfficial =
          domain === mainDomain ||
          domain.endsWith("." + mainDomain);
    
        if (!isOfficial) {
          score += 45;
          flags.push("Brand impersonation: " + brand);
        }
      }
    }
    if (/login|signin|account|verify|secure|update|confirm|auth/.test(u.pathname)) {
      score += 15; flags.push("Suspicious path: " + u.pathname.slice(0,30));
    }
  } catch {}

  const urgency = [
    "your account has been suspended","verify your account","confirm your identity",
    "unusual activity","act now","account will be closed","update your payment",
    "verify immediately","click here to verify","your account is at risk"
  ];
  for (const phrase of urgency) {
    if (combined.includes(phrase)) { score += 20; flags.push(`Urgency: "${phrase}"`); }
  }

  if ((combined.includes("password") || combined.includes("log in")) && combined.includes("enter your")) {
    for (const brand of PHISHING_BRANDS) {
      if (combined.includes(brand)) { score += 30; flags.push("Fake " + brand + " login page"); }
    }
  }

  return { score: Math.min(score, 100), flags };
}

function rulesMalcode(code, filename) {
  let score = 0;
  const flags = [];

  if (/\.(exe|scr|bat|cmd|ps1|vbs|jar|hta|pif|com|dll|msi|reg)$/i.test(filename || "")) {
    score += 40; flags.push("Dangerous extension: ." + (filename || "").split(".").pop());
  }

  if (code) {
    for (const p of MALCODE_PATTERNS) {
      if (p.re.test(code)) { score += 28; flags.push(p.label); }
    }
    if (code.length > 300) {
      const ent = calcEntropy(code.slice(0, 1000));
      if (ent > 5.8) { score += 25; flags.push("Very high entropy (" + ent.toFixed(2) + ")"); }
      else if (ent > 5.3) { score += 12; flags.push("Elevated entropy (" + ent.toFixed(2) + ")"); }
    }
    if (/[A-Za-z0-9+/]{300,}={0,2}/.test(code)) { score += 20; flags.push("Large base64 blob"); }
  }

  return { score: Math.min(score, 100), flags };
}

function rulesEmail(subject, sender, body) {
  let score = 0;
  const flags = [];
  const combined = ((subject || "") + " " + (sender || "") + " " + (body || "")).toLowerCase();

  if (sender) {
    for (const brand of PHISHING_BRANDS) {
      if (sender.toLowerCase().includes(brand)) {
        const valid = ["@"+brand+".com","@"+brand+".org","@"+brand+".net"];
        if (!valid.some(v => sender.toLowerCase().endsWith(v))) {
          score += 50; flags.push("Sender spoofs " + brand + ": " + sender);
        }
      }
    }
    if (/@(gmail|yahoo|hotmail|outlook)\./i.test(sender) &&
        /(bank|support|security|noreply|admin|paypal|amazon|apple)/i.test(sender)) {
      score += 40; flags.push("Business impersonation via free email");
    }
  }

  const urgentWords = [
    "account suspended","verify now","unusual sign-in","security alert",
    "action required","your account","payment failed","you won","claim your",
    "expires today","limited time","confirm now","urgent"
  ];
  for (const w of urgentWords) {
    if (combined.includes(w)) { score += 12; flags.push(`Urgent: "${w}"`); }
  }

  if (body) {
    if (body.includes("password") && body.includes("enter")) { score += 35; flags.push("Email asks for password"); }
    if (body.includes("credit card") || body.includes("bank account")) { score += 40; flags.push("Email requests financial details"); }
    if (/bit\.ly|tinyurl|shorturl|ow\.ly|t\.co\/[a-z0-9]{6}/i.test(body)) { score += 20; flags.push("Shortened/obfuscated URLs"); }
    const linkCount = (body.match(/https?:\/\//gi) || []).length;
    if (linkCount > 6) { score += 10; flags.push(linkCount + " links in email"); }
  }

  return { score: Math.min(score, 100), flags };
}

// ================================================================
// GOOGLE SAFE BROWSING CHECK
// ================================================================
async function checkSafeBrowsing(url) {
  if (!GOOGLE_SAFE_BROWSING_KEY || GOOGLE_SAFE_BROWSING_KEY === "YOUR_GOOGLE_SAFE_BROWSING_KEY") {
    return { threats: [], error: "No GSB key" };
  }
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "shieldai", clientVersion: "2.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
          }
        })
      }
    );
    const data = await res.json();
    if (data.matches && data.matches.length > 0) {
      return { threats: data.matches.map(m => m.threatType), flagged: true };
    }
    return { threats: [], flagged: false };
  } catch (e) {
    return { threats: [], error: e.message };
  }
}

// ================================================================
// VIRUSTOTAL CHECK
// ================================================================
async function checkVirusTotal(url) {
  if (!VIRUSTOTAL_KEY || VIRUSTOTAL_KEY === "YOUR_VIRUSTOTAL_KEY") {
    return { malicious: 0, error: "No VT key" };
  }
  try {
    // URL scan
    const urlId = Buffer.from(url).toString("base64").replace(/=/g, "");
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { "x-apikey": VIRUSTOTAL_KEY }
    });
    if (!res.ok) return { malicious: 0, error: "VT not found" };
    const data = await res.json();
    const stats = data?.data?.attributes?.last_analysis_stats || {};
    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      flagged: (stats.malicious || 0) > 0
    };
  } catch (e) {
    return { malicious: 0, error: e.message };
  }
}

// ================================================================
// ROUTES
// ================================================================

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ShieldAI backend running", version: "2.0" });
});

// ── MAIN WEBSITE SCAN ─────────────────────────────────────────────
app.post("/scan/website", async (req, res) => {
  const { url, title, bodyText } = req.body;
  if (!url) return res.status(400).json({ error: "url required" });

  console.log("[ShieldAI] Website scan:", url.slice(0, 80));

  // 1. Rules (instant)
  const piracy = rulesPiracy(url, title, bodyText);
  const phishing = rulesPhishing(url, title, bodyText);

  // 2. Safe Browsing (async)
  const sbResult = await checkSafeBrowsing(url);

  let sbScore = 0;
  if (sbResult.flagged) {
    sbScore = 90;
    sbResult.threats.forEach(t => phishing.flags.push("Google Safe Browsing: " + t));
  }

  // 3. OpenRouter AI (async)
  let aiResult = null;
  try {
    const aiText = await callAIText(
      `You are a cybersecurity expert. Analyze this website thoroughly.\n` +
      `URL: ${url}\nTitle: ${title || "N/A"}\n` +
      `Content preview: ${(bodyText || "").slice(0, 1000)}\n` +
      `Pre-scan: piracy_score=${piracy.score}, phishing_score=${phishing.score}\n\n` +
      `Check ALL threats: phishing, piracy (torrents/streaming/warez/cracked software), ` +
      `malware distribution, scam, social engineering, harmful content.\n` +
      `Reply ONLY with JSON:\n` +
      `{"phishing":0-100,"piracy":0-100,"malware":0-100,"scam":0-100,` +
      `"flags":["f1","f2","f3"],"verdict":"one sentence","safe":true/false}`
    );
    aiResult = parseJSON(aiText);
  } catch (e) {
    console.warn("[ShieldAI] OpenRouter error:", e.message);
  }

  // Merge results
  const finalPhishing = Math.max(phishing.score, sbScore, aiResult?.phishing || 0);
  const finalPiracy = Math.max(piracy.score, aiResult?.piracy || 0);
  const finalMalware = Math.max(aiResult?.malware || 0, sbResult.flagged ? 80 : 0);
  const finalScore = Math.max(finalPhishing, finalPiracy, finalMalware, aiResult?.scam || 0);

  const allFlags = [
    ...phishing.flags,
    ...piracy.flags,
    ...(aiResult?.flags || []).map(f => "🤖 " + f)
  ];
  if (aiResult?.verdict) allFlags.unshift("OpenRouter: " + aiResult.verdict);

  const threatType = finalPiracy > finalPhishing ? "piracy" : "phishing";

  res.json({
    score: Math.min(finalScore, 100),
    phishingScore: Math.min(finalPhishing, 100),
    piracyScore: Math.min(finalPiracy, 100),
    malwareScore: Math.min(finalMalware, 100),
    flags: allFlags,
    threatType: finalScore >= 50 ? threatType : "safe",
    verdict: aiResult?.verdict || (finalScore >= 65 ? "Threat detected" : "Clean"),
    sources: {
      rules: true,
      safeBrowsing: !sbResult.error,
      ai: !!aiResult
    }
  });
});

// ── EMAIL SCAN ────────────────────────────────────────────────────
app.post("/scan/email", async (req, res) => {
  const { subject, sender, body } = req.body;
  console.log("[ShieldAI] Email scan:", subject?.slice(0, 40));

  const rules = rulesEmail(subject, sender, body);

  let aiResult = null;
  try {
    const aiText = await callAIText(
      `Email security expert. Is this email phishing or scam?\n` +
      `Subject: ${subject || "N/A"}\nSender: ${sender || "N/A"}\n` +
      `Body: ${(body || "").slice(0, 800)}\n` +
      `Rules pre-score: ${rules.score}\n\n` +
      `Reply ONLY with JSON:\n` +
      `{"phishing_score":0-100,"is_phishing":true/false,` +
      `"red_flags":["f1","f2","f3"],"verdict":"one sentence"}`
    );
    aiResult = parseJSON(aiText);
  } catch (e) {
    console.warn("[ShieldAI] OpenRouter email error:", e.message);
  }

  const finalScore = Math.max(rules.score, aiResult?.phishing_score || 0);
  const finalFlags = [
    ...rules.flags,
    ...(aiResult?.red_flags || []).map(f => "🤖 " + f)
  ];
  if (aiResult?.verdict) finalFlags.unshift("OpenRouter: " + aiResult.verdict);

  res.json({
    score: Math.min(finalScore, 100),
    threat: finalScore >= 50,
    flags: finalFlags,
    verdict: aiResult?.verdict || (finalScore >= 50 ? "Phishing detected" : "Clean")
  });
});

// ── SCRIPT/CODE SCAN ──────────────────────────────────────────────
app.post("/scan/code", async (req, res) => {
  const { code, filename } = req.body;
  console.log("[ShieldAI] Code scan:", filename || "inline");

  const rules = rulesMalcode(code, filename);

  let aiResult = null;
  try {
    const aiText = await callAIText(
      `Malware analyst. Analyze this code for malicious behavior.\n` +
      `Filename: ${filename || "unknown"}\n` +
      `Code: ${(code || "").slice(0, 1000)}\n` +
      `Rules pre-score: ${rules.score}\n\n` +
      `Check: obfuscation, data exfiltration, droppers, keyloggers, cryptominers.\n` +
      `Reply ONLY with JSON:\n` +
      `{"malicious":true/false,"severity":0-100,"threats":["t1","t2"],"verdict":"one sentence"}`
    );
    aiResult = parseJSON(aiText);
  } catch (e) {
    console.warn("[ShieldAI] OpenRouter code error:", e.message);
  }

  const finalScore = Math.max(rules.score, aiResult?.severity || 0);
  const finalFlags = [
    ...rules.flags,
    ...(aiResult?.threats || []).map(t => "🤖 " + t)
  ];
  if (aiResult?.verdict) finalFlags.unshift("OpenRouter: " + aiResult.verdict);

  res.json({
    score: Math.min(finalScore, 100),
    threat: finalScore >= 50,
    flags: finalFlags,
    verdict: aiResult?.verdict || (finalScore >= 50 ? "Malicious code detected" : "Clean")
  });
});

// ── IMAGE SCAN — detects AI-generated images ─────────────────────
app.post("/scan/image", async (req, res) => {
  const { imageUrl, imageBase64, mediaType } = req.body;
  let score = 0;
  const flags = [];
  let source = "rules";

  console.log("[ShieldAI] Image scan:", (imageUrl || "base64 data").slice(0, 80));

  // ── STEP 1: Rule-based pre-checks ────────────────────────────────
  if (imageUrl) {
    try {
      const hostname = new URL(imageUrl).hostname.toLowerCase();
      // Known AI image generation services
      const aiHosts = ["midjourney","dalle","openai","stability.ai","nightcafe",
        "dreamstudio","runwayml","replicate","leonardo.ai","firefly.adobe","bing.com/images/create"];
      if (aiHosts.some(h => hostname.includes(h) || imageUrl.includes(h))) {
        score += 80;
        flags.push("Image sourced from known AI generation service");
      }
      // Suspicious generic hosting (common for AI images)
      if (/cdn\.discordapp|media\.discordapp/.test(imageUrl)) {
        score += 20; flags.push("Discord CDN (common for AI image sharing)");
      }
    } catch {}
  }

  // ── STEP 2: Try to get image and send to OpenRouter Vision ────────────
  let imgBase64 = imageBase64 || null;
  let imgMediaType = mediaType || "image/jpeg";

  // If URL provided but no base64, fetch the image
  if (!imgBase64 && imageUrl) {
    try {
      const fetched = await fetchImageAsBase64(imageUrl);
      imgBase64 = fetched.base64;
      imgMediaType = fetched.mediaType;
      flags.push("Image fetched: " + fetched.sizeKB + "KB, type: " + imgMediaType);
    } catch (e) {
      console.warn("[ShieldAI] Could not fetch image:", e.message);
      flags.push("Could not fetch image for analysis: " + e.message);
    }
  }

  // ── STEP 3: OpenRouter Vision Analysis ───────────────────────────────
  let aiResult = null;
  if (imgBase64) {
    try {
      source = "OpenRouter-vision";
      const { imageUrl } = req.body;

      // ADD THIS ABOVE the call
      const prompt = `
      Analyze this image and determine whether it is AI-generated or a real photograph.

      Respond ONLY in JSON:
      {
        "real_score": number (0-100),
        "ai_score": number (0-100),
        "reason": "short explanation"
      }
      `;

      const aiText = await callOpenRouterVision(imageUrl, prompt,
        `You are an expert at detecting AI-generated images vs real photographs.

        Analyze this image carefully for these AI generation artifacts:
        - Perfect symmetry or unnaturally smooth skin/textures
        - Distorted or fused fingers, hands, or limbs
        - Incoherent background details or impossible geometry
        - Text or signs with garbled/nonsense letters
        - Unnaturally perfect lighting with no environmental shadows
        - Eyes that are glassy, asymmetric, or oddly reflective
        - Hair that merges into background or has unrealistic flow
        - Accessories or jewelry that morph or defy physics
        - Facial features that are too perfect or subtly "wrong"
        - Watermarks from Midjourney, DALL-E, Stable Diffusion, etc.

        Also check if this could be a DEEPFAKE:
        - Facial boundary artifacts or blending seams
        - Unnatural blinking patterns or expressions
        - Lighting inconsistency between face and background

        Reply ONLY with JSON:
        {
          "ai_score": 0-100,
          "is_ai_generated": true/false,
          "is_deepfake": true/false,
          "confidence": "low/medium/high",
          "artifacts": ["artifact1", "artifact2"],
          "verdict": "one clear sentence",
          "generator": "Midjourney/DALL-E/Stable Diffusion/Unknown/Real"
        }`
      );
      aiResult = parseJSON(aiText);
      if (aiResult) {
        score = Math.max(score, aiResult.ai_score || 0);
        if (aiResult.is_ai_generated) flags.unshift("🤖 AI GENERATED IMAGE DETECTED");
        if (aiResult.is_deepfake) { score = Math.max(score, 85); flags.unshift("⚠️ POSSIBLE DEEPFAKE DETECTED"); }
        if (aiResult.generator && aiResult.generator !== "Real") flags.push("Generator: " + aiResult.generator);
        if (aiResult.confidence) flags.push("Confidence: " + aiResult.confidence);
        (aiResult.artifacts || []).forEach(a => flags.push("Artifact: " + a));
      }
    } catch (e) {
      console.warn("[ShieldAI] OpenRouter Vision error:", e.message);
      flags.push("Vision AI unavailable: " + e.message);
    }
  } else {
    // No image available — use URL-based heuristics only
    flags.push("Image could not be analyzed (URL-only scan)");
    try {
      const urlHint = await callAIText(
        "Based only on this image URL, guess if it might be AI-generated.\n" +
        "URL: " + imageUrl + "\n" +
        "Reply ONLY with JSON: {\"ai_score\":0-100,\"verdict\":\"one sentence\"}"
      );
      const hint = parseJSON(urlHint);
      if (hint) { score = Math.max(score, hint.ai_score || 0); }
    } catch {}
  }

  res.json({
    score: Math.min(score, 100),
    is_ai: score >= 50,
    is_deepfake: aiResult?.is_deepfake || false,
    confidence: aiResult?.confidence || "low",
    generator: aiResult?.generator || "Unknown",
    flags: flags,
    verdict: aiResult?.verdict || (score >= 65 ? "Likely AI-generated" : score >= 35 ? "Possibly AI-generated" : "Likely real photo"),
    source: source
  });
});

// ── DOWNLOAD/FILE SCAN ────────────────────────────────────────────
app.post("/scan/download", async (req, res) => {
  const { filename, fileUrl } = req.body;
  const rules = rulesMalcode("", filename);

  // Check with VirusTotal if URL available
  let vtResult = null;
  if (fileUrl) vtResult = await checkVirusTotal(fileUrl);

  let vtScore = 0;
  const vtFlags = [];
  if (vtResult?.flagged) {
    vtScore = 90;
    vtFlags.push(`VirusTotal: ${vtResult.malicious} engines flagged as malicious`);
  }

  const finalScore = Math.max(rules.score, vtScore);
  res.json({
    score: Math.min(finalScore, 100),
    threat: finalScore >= 40,
    flags: [...rules.flags, ...vtFlags],
    verdict: finalScore >= 40 ? "Block this download" : "Appears safe"
  });
});

app.listen(PORT, () => {
  console.log(`✅ ShieldAI backend running on port ${PORT}`);
  console.log("OpenRouter Key Loaded:", !!OPENROUTER_API_KEY);
  console.log(`   GSB key:    ${GOOGLE_SAFE_BROWSING_KEY !== "YOUR_GOOGLE_SAFE_BROWSING_KEY" ? "✓ configured" : "✗ not set (optional)"}`);
  console.log(`   VT key:     ${VIRUSTOTAL_KEY !== "YOUR_VIRUSTOTAL_KEY" ? "✓ configured" : "✗ not set (optional)"}`);
});
