// ShieldAI Backend Server
// Deploy free on Render.com or Railway.app
// Or run locally: node server.js
require("dotenv").config();

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

// ── LOCAL AI MODELS (zero API key, zero cost) ─────────────────────
let _textClassifierPromise = null;
let _imageClassifierPromise = null;

function getTextClassifier() {
  if (!_textClassifierPromise) {
    _textClassifierPromise = import('@xenova/transformers').then(({ pipeline }) =>
      pipeline('zero-shot-classification', 'Xenova/mobilebert-uncased-mnli')
    );
  }
  return _textClassifierPromise;
}

function getImageClassifier() {
  if (!_imageClassifierPromise) {
    _imageClassifierPromise = import('@xenova/transformers').then(({ pipeline }) =>
      pipeline('image-classification', 'Falconsai/AI-image-detector')
    );
  }
  return _imageClassifierPromise;
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
  "yggtorrent","cpasbien","torrent9","fztvseries","o2tvseries","extratorrents",
  // Expanded list (50+ new domains)
  "flixhq","hdtoday","myflixer","bflixz","dopebox","kissasian","dramacool",
  "gogoanime","9anime","animepahe","zoro.to","aniwave","animesuge.to",
  "watchserieshd","primewire","0123movie","ymovies","afdah","vumoo",
  "novafile","rapidgator","uploaded","turbobit","nitroflare","ddownload",
  "apkmody","happymod","apkmirror-mod","luckypatcher",
  "z-lib","annas-archive","trantor","mobilism","audiobookbay",
  "y2mate","savefrom","clipconverter","mp3juices","flvto",
  "desiremovies","katmoviehd","extramovies","ssrmovies","cinemavilla",
  "1tamilmv","tamilblasters","dvdplay","uwatchfree","5movierulz"
];

const PIRACY_KEYWORDS = [
  "download torrent", "magnet link", "torrent file", "seeders", "leechers",
  "free download full movie", "watch online free hd", "free stream hd",
  "download full album free", "cracked software", "serial key generator",
  "keygen download", "license key free", "activation key free",
  "nulled script", "warez download", "pirated game", "free premium account",
  "cracked apk", "mod apk unlimited", "bypass premium", "scene release",
  "cracked by", "repack by", "fitted by", "compressed by",
  // Expanded keywords (20+ new)
  "watch free online", "stream free", "download free movie", "free streaming",
  "crack download", "patch download", "full version free", "premium free download",
  "pirated copy", "bootleg", "cam quality", "dvdscr", "hdts", "webrip", "brrip",
  "no subscription needed", "bypass paywall", "free premium access",
  "torrent download", "direct download link", "ddl", "mega link", "mediafire link"
];

const PHISHING_BRANDS = [
  "paypal","apple","google","microsoft","amazon","netflix","facebook",
  "instagram","twitter","linkedin","dropbox","adobe","chase","wellsfargo",
  "bankofamerica","citibank","barclays","hsbc","santander","sbi","hdfc","icici",
  "binance","coinbase","metamask","upwork","fiverr",
  // Expanded brands (30+ new)
  "dhl","fedex","ups","usps","royalmail","stripe","square","venmo",
  "zelle","cashapp","wise","revolut","robinhood","etrade","fidelity",
  "steam","epicgames","roblox","discord","telegram","whatsapp","signal",
  "uber","lyft","airbnb","booking","expedia",
  "walmart","target","bestbuy","costco","ebay","alibaba","aliexpress",
  "icloud","outlook","protonmail","zoho",
  "github","gitlab","bitbucket","heroku","vercel","netlify",
  "aws","azure","gcp","digitalocean","cloudflare"
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
  { re: /\\u00[0-9a-f]{2}(\\u00[0-9a-f]{2}){10,}/i, label: "Unicode escape obfuscation" },
  // 15+ new patterns
  { re: /document\.cookie\s*=.*;\s*path/i, label: "Cookie manipulation" },
  { re: /localStorage\.(getItem|setItem)\s*\(.{0,60}(password|token|credential)/i, label: "localStorage credential theft" },
  { re: /addEventListener\s*\(\s*['"]key(up|down|press)['"]/i, label: "Keystroke capture listener" },
  { re: /<iframe[^>]+style\s*=\s*['"][^'"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0)/i, label: "Hidden iframe" },
  { re: /new\s+WebSocket\s*\(\s*['"]wss?:\/\/(?!localhost)/i, label: "WebSocket C2 channel" },
  { re: /navigator\.clipboard\.(read|writeText)/i, label: "Clipboard theft" },
  { re: /window\.showOpenFilePicker|window\.showSaveFilePicker|FileSystemAccess/i, label: "Filesystem access API" },
  { re: /document\.execCommand\s*\(\s*['"]copy['"]\)/i, label: "Programmatic clipboard copy" },
  { re: /XMLHttpRequest.{0,200}\.send\(.{0,100}(password|credential|token)/i, label: "XHR credential exfiltration" },
  { re: /setTimeout\s*\(\s*['"][^'"]{200,}['"]/i, label: "String-based setTimeout (deferred eval)" },
  { re: /setInterval\s*\(\s*['"][^'"]{200,}['"]/i, label: "String-based setInterval (deferred eval)" },
  { re: /import\s*\(\s*['"]data:/i, label: "Data URI dynamic import" },
  { re: /Function\.prototype\.constructor\s*\(/i, label: "Indirect Function constructor" },
  { re: /\bprocess\s*\[\s*['"]binding['"]\s*\]/i, label: "Node.js process binding access" },
  { re: /require\s*\(\s*['"]child_process['"]\s*\)/i, label: "child_process require" }
];

// ================================================================
// PRE-COMPILED REGEX PATTERNS (performance)
// ================================================================
const RE_TYPOSQUAT = /paypa1|pay-pal|paypai|arnazon|amaz0n|g00gle|microsofl|appl3|app1e|faceb00k|1nstagram|g0ogle|c1tibank|wellsfarg0/;
const RE_TORRENT_FORMAT = /\b(bluray|blu-ray|bdrip|dvdrip|hdtv|webrip|brrip|hdts|dvdscr|cam\b|x264|x265|hevc|avc|xvid|divx|h\.?264|h\.?265)\b/i;
const RE_TV_EPISODE = /\bS\d{2}E\d{2}\b|\bseason\s+\d+\s+episode\s+\d+\b/i;
const RE_DOUBLE_EXT = /\.(pdf|doc|docx|txt|jpg|png)\.(exe|bat|cmd|ps1|vbs|scr|jar)$/i;
const RE_BASE64_PARAM = /[?&][^=]+=([A-Za-z0-9+/]{40,}={0,2})(&|$)/;
const RE_REDIRECT_CHAIN = /[?&](redirect|return|next|url|goto|target|dest|destination)\s*=\s*https?:\/\//i;
const RE_DGA_DOMAIN = /^[a-z]{8,15}\.(xyz|top|tk|ml|ga|cf|gq|pw)$/;
const RE_BRAND_SUBDOMAIN = /^(paypal|apple|google|microsoft|amazon|netflix|facebook|instagram|twitter|linkedin|dropbox|adobe|chase|wellsfargo|bankofamerica|citibank|barclays|hsbc|stripe|steam|discord|github)\.[a-z0-9-]+\.[a-z]{2,}$/;
const RE_OBFUS_VARS = /\b_0x[0-9a-f]{4,}\b/i;
const RE_HEAVY_CONCAT = /(['"][^'"]{0,30}['"]\s*\+\s*){20,}/;

// ================================================================
// LRU SCAN RESULT CACHE (5-minute TTL, 1000-entry max)
// ================================================================
const SCAN_CACHE_TTL_MS = 5 * 60 * 1000;
const SCAN_CACHE_MAX = 1000;
const _scanCache = new Map();

function getCachedScan(key) {
  const entry = _scanCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > SCAN_CACHE_TTL_MS) { _scanCache.delete(key); return null; }
  // Refresh insertion order for LRU
  _scanCache.delete(key);
  _scanCache.set(key, entry);
  return entry.value;
}

function setCachedScan(key, value) {
  if (_scanCache.has(key)) _scanCache.delete(key);
  else if (_scanCache.size >= SCAN_CACHE_MAX) {
    // Evict oldest entry (first inserted)
    _scanCache.delete(_scanCache.keys().next().value);
  }
  _scanCache.set(key, { ts: Date.now(), value });
}

// ================================================================
// URL REPUTATION ANALYSIS
// ================================================================
function analyzeUrlReputation(url) {
  const flags = [];
  let score = 0;
  try {
    const u = new URL(url);
    const hostname = u.hostname.toLowerCase().replace(/^www\./, "");
    const fullUrl = url;

    // Double extension (.pdf.exe etc.)
    if (RE_DOUBLE_EXT.test(u.pathname)) {
      score += 70; flags.push("Double extension (masquerading file)");
    }
    // Base64 in URL params
    if (RE_BASE64_PARAM.test(fullUrl)) {
      score += 30; flags.push("Base64-encoded URL parameter");
    }
    // Redirect chain
    if (RE_REDIRECT_CHAIN.test(fullUrl)) {
      score += 35; flags.push("Open redirect chain detected");
    }
    // Auto-generated / DGA domain
    if (RE_DGA_DOMAIN.test(hostname)) {
      score += 40; flags.push("Likely auto-generated (DGA) domain");
    }
    // Brand in subdomain (brand.attacker.com pattern)
    if (RE_BRAND_SUBDOMAIN.test(hostname)) {
      score += 55; flags.push("Brand name used as subdomain");
    }
  } catch {}
  return { score: Math.min(score, 100), flags };
}


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

  // Content structure detection
  if (RE_TORRENT_FORMAT.test(combined)) {
    score += 30; flags.push("Torrent release format tag detected");
  }
  if (RE_TV_EPISODE.test(combined)) {
    score += 20; flags.push("TV episode download pattern detected");
  }
  const dlLinkCount = (combined.match(/https?:\/\/[^\s"'<>]+\.(torrent|zip|rar|mkv|mp4|avi)/gi) || []).length;
  if (dlLinkCount >= 5) {
    score += 25; flags.push(`Excessive download links (${dlLinkCount})`);
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
    if (RE_TYPOSQUAT.test(domain)) {
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
    // Data URI phishing page
    if (url.startsWith("data:text/html")) {
      score += 80; flags.push("Data URI phishing page");
    }
    // Long URL
    if (url.length > 500) {
      score += 15; flags.push("Excessively long URL (" + url.length + " chars)");
    }
    // @ in URL host (credential obfuscation)
    if (u.username || u.password) {
      score += 60; flags.push("@ symbol in URL (credential obfuscation)");
    }
    // Punycode / IDN domain
    if (domain.startsWith("xn--") || domain.includes(".xn--")) {
      score += 45; flags.push("Punycode/IDN domain (possible homograph)");
    }
  } catch {}

  const urgency = [
    "your account has been suspended","verify your account","confirm your identity",
    "unusual activity","act now","account will be closed","update your payment",
    "verify immediately","click here to verify","your account is at risk",
    // 15+ new urgency phrases
    "we noticed suspicious activity","unauthorized access attempt","your password has been compromised",
    "immediate action required","your account will be permanently deleted","verify your billing information",
    "you have been selected","congratulations you won","click below to claim",
    "your package is waiting","delivery attempt failed","reschedule your delivery",
    "your subscription will expire","payment method declined","update billing now"
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

    // Multi-layer obfuscation detection
    if (RE_HEAVY_CONCAT.test(code)) {
      score += 30; flags.push("Heavy string concatenation (possible obfuscation)");
    }
    if (RE_OBFUS_VARS.test(code)) {
      score += 25; flags.push("Obfuscated variable names (_0x... pattern)");
    }
    if (/\bdebugger\b/.test(code)) {
      score += 20; flags.push("Anti-debugging (debugger statement)");
    }
    if (/console\s*=\s*\{|console\.(log|warn|error)\s*=\s*function/.test(code)) {
      score += 20; flags.push("Console hijacking detected");
    }
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

    // Mismatched Reply-To domain
    const replyToMatch = combined.match(/reply-to:\s*\S+@(\S+)/i);
    const senderDomainMatch = sender.match(/@([^>]+)/);
    if (replyToMatch && senderDomainMatch && replyToMatch[1].toLowerCase() !== senderDomainMatch[1].toLowerCase()) {
      score += 35; flags.push("Mismatched Reply-To domain");
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

    // Fake attachment + link pattern
    if (/(see attached|see the attached|attached file)/i.test(body) && /click here/i.test(body)) {
      score += 30; flags.push("Fake attachment with click-here link");
    }
    // Phishing grammar markers
    if (/dear customer|dear valued|kindly click|do the needful/i.test(body)) {
      score += 25; flags.push("Phishing grammar marker detected");
    }
    // Executable extension mentions
    if (/\.(exe|ps1|vbs|bat|cmd|scr)\b/i.test(body)) {
      score += 30; flags.push("Executable file extension mentioned in email");
    }
    // Cryptocurrency / wire transfer requests
    if (/bitcoin|wire transfer|western union|moneygram|gift card|itunes card/i.test(body)) {
      score += 35; flags.push("Cryptocurrency or wire transfer request");
    }
    // BEC (Business Email Compromise) pattern
    if (/(ceo|chief executive|president|director).{0,100}(urgent|confidential).{0,100}(wire|transfer|payment)/i.test(body)) {
      score += 45; flags.push("BEC pattern: executive + urgent + payment");
    }
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

  // Check cache first
  const cacheKey = `website:${url}`;
  const cached = getCachedScan(cacheKey);
  if (cached) return res.json(cached);

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

  // 3. Local AI Classification (improved prompt engineering)
  let aiResult = null;
  try {
    const classifier = await getTextClassifier();
    const textToAnalyze = `Analyze this web page for threats. URL: ${url} Page title: ${title || 'unknown'} Content snippet: ${(bodyText || '').slice(0, 600)}`;
    const result = await classifier(textToAnalyze, [
      'phishing credential theft',
      'piracy copyright infringement',
      'malware distribution',
      'scam fraud deception',
      'legitimate safe content'
    ]);
    const labelMap = {};
    result.labels.forEach((label, i) => { labelMap[label] = Math.round(result.scores[i] * 100); });
    const topLabel = result.labels[0];
    aiResult = {
      phishing: labelMap['phishing credential theft'] || 0,
      piracy: labelMap['piracy copyright infringement'] || 0,
      malware: labelMap['malware distribution'] || 0,
      scam: labelMap['scam fraud deception'] || 0,
      flags: [],
      verdict: topLabel !== 'legitimate safe content' ? `AI detected possible ${topLabel}` : 'Content appears safe',
      safe: topLabel === 'legitimate safe content'
    };
  } catch (e) {
    console.warn("[ShieldAI] Local AI error:", e.message);
  }

  // Restore raw score merging (no weight multipliers)
  const finalPhishing = Math.max(phishing.score, sbScore, aiResult?.phishing || 0);
  const finalPiracy = Math.max(piracy.score, aiResult?.piracy || 0);
  const finalMalware = Math.max(aiResult?.malware || 0, sbResult.flagged ? 80 : 0);
  const finalScam = aiResult?.scam || 0;
  const finalScore = Math.max(finalPhishing, finalPiracy, finalMalware, finalScam);

  const allFlags = [
    ...phishing.flags,
    ...piracy.flags,
    ...(aiResult?.flags || []).map(f => "🤖 " + f)
  ];
  if (aiResult?.verdict) allFlags.unshift("AI: " + aiResult.verdict);

  const threatType = finalPiracy > finalPhishing ? "piracy" : "phishing";

  // Confidence based on distinct detection source count (threshold >= 30 for meaningful signal)
  const sourceCount = [
    phishing.score >= 30 || piracy.score >= 30,
    sbResult.flagged,
    !!aiResult && !aiResult.safe
  ].filter(Boolean).length;
  const confidence = sourceCount >= 2 ? "high" : sourceCount === 1 ? "medium" : "low";

  const result = {
    score: Math.min(Math.round(finalScore), 100),
    phishingScore: Math.min(Math.round(finalPhishing), 100),
    piracyScore: Math.min(Math.round(finalPiracy), 100),
    malwareScore: Math.min(Math.round(finalMalware), 100),
    flags: allFlags,
    threatType: finalScore >= 50 ? threatType : "safe",
    verdict: aiResult?.verdict || (finalScore >= 65 ? "Threat detected" : "Clean"),
    confidence,
    sources: {
      rules: true,
      safeBrowsing: !sbResult.error,
      ai: !!aiResult
    }
  };

  setCachedScan(cacheKey, result);
  res.json(result);
});

// ── EMAIL SCAN ────────────────────────────────────────────────────
app.post("/scan/email", async (req, res) => {
  const { subject, sender, body } = req.body;
  console.log("[ShieldAI] Email scan:", subject?.slice(0, 40));

  const rules = rulesEmail(subject, sender, body);

  let aiResult = null;
  try {
    const classifier = await getTextClassifier();
    const emailText = `Classify this email for threats. Subject: ${subject || ''} From: ${sender || ''} Body: ${(body || '').slice(0, 600)}`;
    const result = await classifier(emailText, [
      'phishing email credential theft',
      'scam fraud email',
      'spam unsolicited email',
      'legitimate genuine email'
    ]);
    const topLabel = result.labels[0];
    const topScore = Math.round(result.scores[0] * 100);
    const isThreat = topLabel !== 'legitimate genuine email';
    aiResult = {
      phishing_score: isThreat ? topScore : 0,
      is_phishing: isThreat && topScore >= 50,
      red_flags: isThreat ? [`AI: ${topLabel} (${topScore}%)`] : [],
      verdict: isThreat ? `AI detected: ${topLabel}` : 'Email appears legitimate'
    };
  } catch (e) {
    console.warn("[ShieldAI] Local AI email error:", e.message);
  }

  const finalScore = Math.max(rules.score, aiResult?.phishing_score || 0);
  const finalFlags = [
    ...rules.flags,
    ...(aiResult?.red_flags || []).map(f => "🤖 " + f)
  ];
  if (aiResult?.verdict) finalFlags.unshift("AI: " + aiResult.verdict);

  const sourceCount = [
    rules.score >= 30,
    !!aiResult?.is_phishing
  ].filter(Boolean).length;
  const confidence = sourceCount >= 2 ? "high" : sourceCount === 1 ? "medium" : "low";

  res.json({
    score: Math.min(finalScore, 100),
    threat: finalScore >= 50,
    flags: finalFlags,
    verdict: aiResult?.verdict || (finalScore >= 50 ? "Phishing detected" : "Clean"),
    confidence
  });
});

// ── SCRIPT/CODE SCAN ──────────────────────────────────────────────
app.post("/scan/code", async (req, res) => {
  const { code, filename } = req.body;
  console.log("[ShieldAI] Code scan:", filename || "inline");

  const rules = rulesMalcode(code, filename);

  let aiResult = null;
  try {
    const classifier = await getTextClassifier();
    const codeText = `Analyze this code for malicious behavior. Filename: ${filename || 'unknown'} Code snippet: ${(code || '').slice(0, 600)}`;
    const result = await classifier(codeText, [
      'malicious code attack payload',
      'obfuscated code hiding intent',
      'keylogger credential stealer',
      'cryptominer resource hijacker',
      'safe benign code'
    ]);
    const topLabel = result.labels[0];
    const topScore = Math.round(result.scores[0] * 100);
    const isMalicious = topLabel !== 'safe benign code';
    aiResult = {
      malicious: isMalicious && topScore >= 50,
      severity: isMalicious ? topScore : 0,
      threats: isMalicious ? [`${topLabel} (${topScore}%)`] : [],
      verdict: isMalicious ? `AI detected: ${topLabel}` : 'Code appears safe'
    };
  } catch (e) {
    console.warn("[ShieldAI] Local AI code error:", e.message);
  }

  const finalScore = Math.max(rules.score, aiResult?.severity || 0);
  const finalFlags = [
    ...rules.flags,
    ...(aiResult?.threats || []).map(t => "🤖 " + t)
  ];
  if (aiResult?.verdict) finalFlags.unshift("AI: " + aiResult.verdict);

  const sourceCount = [
    rules.score >= 30,
    !!aiResult?.malicious
  ].filter(Boolean).length;
  const confidence = sourceCount >= 2 ? "high" : sourceCount === 1 ? "medium" : "low";

  res.json({
    score: Math.min(finalScore, 100),
    threat: finalScore >= 50,
    flags: finalFlags,
    verdict: aiResult?.verdict || (finalScore >= 50 ? "Malicious code detected" : "Clean"),
    confidence
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

  // ── STEP 2: Try to get image for local AI analysis ───────────────
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

  // ── STEP 3: AI Image Detection using Falconsai/AI-image-detector ──
  let aiResult = null;
  if (imgBase64) {
    try {
      source = "local-ai-detector";
      const classifier = await getImageClassifier();
      const dataUrl = `data:${imgMediaType};base64,${imgBase64}`;
      const classResult = await classifier(dataUrl);

      // Falconsai/AI-image-detector outputs labels: "ai_generated" and "real"
      let aiGenScore = 0;
      let realScore = 0;
      for (const r of classResult) {
        if (r.label === 'ai_generated' || r.label === 'artificial' || r.label.toLowerCase().includes('ai')) {
          aiGenScore = Math.round(r.score * 100);
        } else if (r.label === 'real' || r.label === 'human' || r.label.toLowerCase().includes('real')) {
          realScore = Math.round(r.score * 100);
        }
      }

      // Use the AI-generated score directly
      score = Math.max(score, aiGenScore);
      const isAiGenerated = aiGenScore >= 50;
      const confidence = aiGenScore >= 80 ? "high" : aiGenScore >= 50 ? "medium" : "low";

      aiResult = {
        ai_score: aiGenScore,
        is_ai_generated: isAiGenerated,
        is_deepfake: aiGenScore >= 85,  // Very high AI score suggests possible deepfake
        confidence: confidence,
        artifacts: classResult.map(r => `${r.label} (${Math.round(r.score * 100)}%)`),
        verdict: isAiGenerated
          ? `AI-generated image detected (${aiGenScore}% confidence)`
          : `Likely real photograph (${realScore}% confidence)`,
        generator: "Unknown"
      };

      score = Math.max(score, aiResult.ai_score);
      if (aiResult.is_ai_generated) flags.unshift("🤖 AI GENERATED IMAGE DETECTED");
      if (aiResult.is_deepfake) { score = Math.max(score, 85); flags.unshift("⚠️ POSSIBLE DEEPFAKE DETECTED"); }
      if (aiResult.confidence) flags.push("AI Detection Confidence: " + aiResult.confidence);
      (aiResult.artifacts || []).forEach(a => flags.push("Detection: " + a));
    } catch (e) {
      console.warn("[ShieldAI] AI image detection error:", e.message);
      flags.push("AI image detection unavailable: " + e.message);
    }
  } else {
    // No image available — use URL-based text classification
    flags.push("Image could not be analyzed (URL-only scan)");
    try {
      if (imageUrl) {
        const classifier = await getTextClassifier();
        const result = await classifier(
          `Image URL: ${imageUrl}`,
          ['AI generated image', 'real photograph', 'AI artwork', 'stock photo']
        );
        const topLabel = result.labels[0];
        const topScore = Math.round(result.scores[0] * 100);
        if (topLabel !== 'real photograph' && topLabel !== 'stock photo') {
          score = Math.max(score, topScore);
          flags.push(`URL hint: ${topLabel} (${topScore}%)`);
        }
      }
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

app.listen(PORT, async () => {
  console.log(`✅ ShieldAI backend running on port ${PORT}`);
  console.log("   AI Models: Xenova/mobilebert-uncased-mnli (text) + Falconsai/AI-image-detector (vision)");
  console.log(`   GSB key:    ${GOOGLE_SAFE_BROWSING_KEY !== "YOUR_GOOGLE_SAFE_BROWSING_KEY" ? "✓ configured" : "✗ not set (optional)"}`);
  console.log(`   VT key:     ${VIRUSTOTAL_KEY !== "YOUR_VIRUSTOTAL_KEY" ? "✓ configured" : "✗ not set (optional)"}`);

  // Pre-load local AI models in background so first requests are fast
  try {
    console.log('⏳ Loading local AI models...');
    await Promise.all([getTextClassifier(), getImageClassifier()]);
    console.log('✅ Local AI models loaded');
  } catch (e) {
    console.warn('⚠️  Local AI models unavailable:', e.message, '(rule-based detection still active)');
  }
});
