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

// Pre-compiled regex patterns for performance
const RE_TORRENT_FORMAT = /\d+\s*(gb|mb)\s*(720p|1080p|2160p|4k|hdrip|webrip|bluray)/i;
const RE_TV_EPISODE = /s\d{1,2}e\d{1,2}/i;
const RE_IP_URL = /^\d{1,3}(\.\d{1,3}){3}$/;
const RE_HIGH_RISK_TLD = /\.(xyz|top|click|loan|work|gq|tk|ml|cf|ga|pw|cc)$/;
const RE_SUSPICIOUS_TLD = /\.(cam|buzz|rest|sbs|vip|live|run|fun|one|club)$/;
const RE_HOMOGRAPH = /[аеіоурсАЕІОУРС]/;
const RE_TYPOSQUAT = /faceb00k|facebo0k|instaqram|1nstagram|g0ogle|micros0ft|netfl1x|arnazon|walmrt|chasebank|wellsfarg0|c1tibank|paypa1|pay-pal|paypai|amaz0n|microsofl|appl3|app1e/;
const RE_SUSP_PATH = /login|signin|account|verify|secure|update|confirm|auth/;
const RE_SHORTENED_URL = /bit\.ly|tinyurl|shorturl|ow\.ly|t\.co\/[a-z0-9]{6}/i;
const RE_EXEC_EXT = /\.(exe|scr|bat|cmd|ps1|vbs|jar|hta|msi|dll)\b/i;

// LRU cache for scan results (5-min TTL, max 1000 entries)
const scanCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const CACHE_MAX_SIZE = 1000;

function getCached(key) {
  const entry = scanCache.get(key);
  if (entry && Date.now() - entry.time < CACHE_TTL) return entry.data;
  scanCache.delete(key);
  return null;
}
function setCache(key, data) {
  // Evict oldest entries until under the size limit
  while (scanCache.size >= CACHE_MAX_SIZE) {
    const oldest = scanCache.keys().next().value;
    scanCache.delete(oldest);
  }
  scanCache.set(key, { data, time: Date.now() });
}

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
  // Additional piracy domains
  "flixhq","hdtoday","myflixer","bflixz","dopebox","kissasian","dramacool",
  "gogoanime","9anime","animepahe","zoro","aniwave","watchserieshd",
  "primewire","0123movie","ymovies","afdah","vumoo",
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
  // Additional keywords
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
  // Additional brands
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
  // Additional patterns
  { re: /document\.cookie\s*=/, label: "Cookie manipulation" },
  { re: /localStorage\.(get|set)Item.{0,50}(password|token|secret|key)/i, label: "Credential storage access" },
  { re: /XMLHttpRequest|fetch\(.+\).+\.then/i, label: "Network request to external server" },
  { re: /\.onkeypress|\.onkeydown|addEventListener\(['"]key/i, label: "Keystroke capture listener" },
  { re: /screen\.(width|height|avail)|navigator\.(platform|userAgent|language)/i, label: "Browser fingerprinting" },
  { re: /new\s+WebSocket\s*\(/, label: "WebSocket connection (possible C2)" },
  { re: /iframe.{0,50}(display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0)/i, label: "Hidden iframe injection" },
  { re: /document\.location\s*=|window\.location\s*=|location\.href\s*=.{0,30}(http|data:)/i, label: "Redirect to external URL" },
  { re: /crypto\.subtle|CryptoJS|sjcl/i, label: "Cryptographic operations (possible ransomware)" },
  { re: /\.exec\s*\(|child_process|spawn\s*\(|execSync/i, label: "System command execution" },
  { re: /require\s*\(\s*['"]fs['"]\)|readFileSync|writeFileSync/i, label: "Filesystem access" },
  { re: /process\.env/i, label: "Environment variable access" },
  { re: /clipboardData|navigator\.clipboard/i, label: "Clipboard access (possible data theft)" },
  { re: /\.zip|\.rar|\.7z.{0,30}download/i, label: "Archive download pattern" },
  { re: /btoa\s*\(|atob\s*\(/, label: "Base64 encoding/decoding" }
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
    if (RE_SUSPICIOUS_TLD.test(hostname) && score === 0) {
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

  // Detect torrent-style content patterns
  if (RE_TORRENT_FORMAT.test(combined)) {
    score += 35; flags.push("Movie/TV release format detected");
  }
  if (RE_TV_EPISODE.test(combined) && /download|stream|watch/i.test(combined)) {
    score += 25; flags.push("TV episode download pattern");
  }
  if ((combined.match(/download/gi) || []).length > 5) {
    score += 15; flags.push("Excessive download links");
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

    if (RE_IP_URL.test(domain)) { score += 55; flags.push("IP address URL"); }
    if (RE_HIGH_RISK_TLD.test(domain)) { score += 25; flags.push("High-risk TLD"); }
    if (RE_HOMOGRAPH.test(domain)) { score += 65; flags.push("Homograph/unicode attack in domain"); }
    if (domain.split(".").length > 5) { score += 20; flags.push("Excessive subdomains"); }
    if (RE_TYPOSQUAT.test(domain)) {
      score += 70; flags.push("Typosquatting detected");
    }
    // Detect brand-in-subdomain attacks: e.g., paypal.login.evil.com
    for (const brand of PHISHING_BRANDS) {
      const parts = domain.split(".");
      if (parts.length >= 3 && parts[0].includes(brand) && !domain.endsWith(brand + ".com")) {
        score += 55; flags.push("Brand-in-subdomain attack: " + brand); break;
      }
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
    if (RE_SUSP_PATH.test(u.pathname)) {
      score += 15; flags.push("Suspicious path: " + u.pathname.slice(0,30));
    }

    // Detect data URI phishing
    if (url.startsWith("data:text/html")) {
      score += 80; flags.push("Data URI phishing page");
    }
    // Check for extremely long URLs (common in phishing)
    if (url.length > 500) {
      score += 15; flags.push("Extremely long URL (" + url.length + " chars)");
    }
    // Check for @ in URL (credential theft pattern)
    if (/@/.test(u.host || "")) {
      score += 60; flags.push("@ symbol in URL (credential harvesting)");
    }
  } catch {}

  const urgency = [
    "your account has been suspended","verify your account","confirm your identity",
    "unusual activity","act now","account will be closed","update your payment",
    "verify immediately","click here to verify","your account is at risk",
    // Additional urgency phrases
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
    const concatCount = (code.match(/\+\s*['"]/g) || []).length;
    if (concatCount > 20) { score += 20; flags.push("Heavy string concatenation (" + concatCount + " joins)"); }

    const obfuscatedVars = (code.match(/\b(var|let|const)\s+[_$][a-z0-9]{1,2}\b/gi) || []).length;
    if (obfuscatedVars > 10) { score += 15; flags.push("Obfuscated variable names (" + obfuscatedVars + " found)"); }

    if (/debugger\s*;/.test(code)) { score += 25; flags.push("Anti-debugging: debugger statement"); }
    if (/console\.(clear|log)\s*=/.test(code)) { score += 20; flags.push("Console hijacking"); }
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
    if (RE_SHORTENED_URL.test(body)) { score += 20; flags.push("Shortened/obfuscated URLs"); }
    const linkCount = (body.match(/https?:\/\//gi) || []).length;
    if (linkCount > 6) { score += 10; flags.push(linkCount + " links in email"); }
  }

  // Check for mismatched reply-to
  if (sender && body) {
    const replyMatch = body.match(/reply[- ]?to\s*:\s*(\S+@\S+)/i);
    const senderDomain = sender.split("@")[1]?.toLowerCase();
    if (replyMatch && senderDomain && !replyMatch[1].toLowerCase().includes(senderDomain)) {
      score += 40; flags.push("Mismatched reply-to address");
    }
  }

  // Check for fake attachment mentions
  if (/attached|attachment|enclosed|see attached/i.test(combined) && /(click|download|open)\s*(here|link|button)/i.test(combined)) {
    score += 25; flags.push("Fake attachment with link");
  }

  // Check for grammar/spelling patterns common in phishing
  const badGrammar = [
    /dear\s+(customer|user|valued|sir|madam)/i,
    /kindly\s+(click|verify|confirm|update)/i,
    /do\s+the\s+needful/i,
    /revert\s+back\s+(to\s+us|at\s+earliest)/i
  ];
  for (const pattern of badGrammar) {
    if (pattern.test(combined)) { score += 10; flags.push("Phishing language pattern"); break; }
  }

  // Check for executable attachment names
  if (RE_EXEC_EXT.test(combined)) {
    score += 50; flags.push("Executable file mentioned in email");
  }

  // Check for cryptocurrency/wire transfer requests
  if (/bitcoin|btc|ethereum|eth|wire\s*transfer|western\s*union|moneygram|gift\s*card/i.test(combined)) {
    score += 35; flags.push("Cryptocurrency/wire transfer request");
  }

  // Check for business email compromise pattern
  if (/ceo|chief\s*executive|director|manager|hr\s*department|it\s*department|legal\s*team/i.test(combined) &&
      /urgent|immediate|confidential|do\s*not\s*share/i.test(combined)) {
    score += 30; flags.push("Business email compromise pattern");
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
// URL REPUTATION HEURISTICS
// ================================================================
function analyzeUrlReputation(url) {
  let score = 0;
  const flags = [];
  try {
    const u = new URL(url);
    // Recently registered domain heuristic (very short domains with numbers)
    if (/[a-z]{2,4}\d{2,6}\./.test(u.hostname)) { score += 15; flags.push("Possibly auto-generated domain"); }
    // Excessive URL parameters
    if (u.searchParams.toString().length > 200) { score += 10; flags.push("Excessive URL parameters"); }
    // Base64 in URL
    if (/[A-Za-z0-9+/]{40,}={0,2}/.test(u.search)) { score += 25; flags.push("Base64 data in URL parameters"); }
    // Double extensions in path
    if (/\.(pdf|doc|xls|jpg)\.(exe|bat|cmd|scr|php|html)/i.test(u.pathname)) {
      score += 60; flags.push("Double extension in URL path");
    }
    // Redirect chains
    if (/redirect|redir|goto|jump|click|track|out\.php/i.test(u.pathname)) {
      score += 15; flags.push("Redirect URL pattern");
    }
  } catch {}
  return { score: Math.min(score, 100), flags };
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

  // Check cache
  const cacheKey = "website:" + url;
  const cached = getCached(cacheKey);
  if (cached) return res.json(cached);

  // 1. Rules (instant)
  const piracy = rulesPiracy(url, title, bodyText);
  const phishing = rulesPhishing(url, title, bodyText);
  const urlRep = analyzeUrlReputation(url);

  // Merge URL reputation flags into phishing
  phishing.score = Math.min(phishing.score + urlRep.score, 100);
  phishing.flags.push(...urlRep.flags);

  // 2. Safe Browsing (async)
  const sbResult = await checkSafeBrowsing(url);

  let sbScore = 0;
  if (sbResult.flagged) {
    sbScore = 90;
    sbResult.threats.forEach(t => phishing.flags.push("Google Safe Browsing: " + t));
  }

  // 3. OpenRouter AI (async) — improved few-shot prompt
  let aiResult = null;
  try {
    const aiPrompt =
      `You are a cybersecurity threat classifier. Given website information, classify threats.\n\n` +
      `EXAMPLES:\n` +
      `- URL: thepiratebay.org, Title: "Download Movies Free" → {"phishing":0,"piracy":95,"malware":10,"scam":0,"safe":false}\n` +
      `- URL: paypal-secure-login.xyz, Title: "Verify Account" → {"phishing":95,"piracy":0,"malware":30,"scam":70,"safe":false}\n` +
      `- URL: github.com, Title: "GitHub" → {"phishing":0,"piracy":0,"malware":0,"scam":0,"safe":true}\n\n` +
      `NOW ANALYZE:\n` +
      `URL: ${url}\nTitle: ${title || "N/A"}\n` +
      `Content: ${(bodyText || "").slice(0, 800)}\n` +
      `Pre-scan scores: phishing=${phishing.score}, piracy=${piracy.score}\n\n` +
      `Reply ONLY JSON: {"phishing":0-100,"piracy":0-100,"malware":0-100,"scam":0-100,"flags":["..."],"verdict":"...","safe":bool}`;
    const aiText = await callAIText(aiPrompt);
    aiResult = parseJSON(aiText);
  } catch (e) {
    console.warn("[ShieldAI] OpenRouter error:", e.message);
  }

  // Weighted score merging: rules provide the baseline; AI and Safe Browsing
  // act as corroborating signals. Weights intentionally don't sum to 1.0 so
  // that multiple independent signals can push the final score higher than any
  // single source alone (e.g. rules + Safe Browsing together give higher scores
  // than either alone), while avoiding inflation when only one source fires.
  const WEIGHT_RULES_HIGH = 0.7;  // rules weight when rule score > 60 (high confidence)
  const WEIGHT_RULES_LOW  = 0.5;  // rules weight when rule score ≤ 60 (moderate confidence)
  const WEIGHT_AI_THREAT  = 0.6;  // AI weight when AI says unsafe
  const WEIGHT_AI_SAFE    = 0.4;  // AI weight when AI says safe
  const WEIGHT_GSB        = 0.9;  // Google Safe Browsing weight (very reliable signal)
  const RULES_HIGH_THRESHOLD = 60; // score above which rules are considered high-confidence

  const rulesConfidence = Math.max(phishing.score, piracy.score) > RULES_HIGH_THRESHOLD
    ? WEIGHT_RULES_HIGH : WEIGHT_RULES_LOW;
  const aiConfidence = aiResult ? (aiResult.safe === false ? WEIGHT_AI_THREAT : WEIGHT_AI_SAFE) : 0;

  const finalPhishing = Math.min(Math.round(
    phishing.score * rulesConfidence + (aiResult?.phishing || 0) * aiConfidence + sbScore * WEIGHT_GSB
  ), 100);
  const finalPiracy = Math.min(Math.round(
    piracy.score * rulesConfidence + (aiResult?.piracy || 0) * aiConfidence
  ), 100);
  const finalMalware = Math.max(aiResult?.malware || 0, sbResult.flagged ? 80 : 0);
  const finalScore = Math.max(finalPhishing, finalPiracy, finalMalware, aiResult?.scam || 0);

  const allFlags = [
    ...phishing.flags,
    ...piracy.flags,
    ...(aiResult?.flags || []).map(f => "🤖 " + f)
  ];
  if (aiResult?.verdict) allFlags.unshift("OpenRouter: " + aiResult.verdict);

  const threatType = finalPiracy > finalPhishing ? "piracy" : "phishing";

  // Confidence level: count distinct detection sources (rules flags, Safe Browsing, AI)
  const totalSignals = (phishing.flags.length > 0 ? 1 : 0) +
    (piracy.flags.length > 0 ? 1 : 0) +
    (sbResult.flagged ? 1 : 0) +
    (aiResult ? 1 : 0) +
    (urlRep.flags.length > 0 ? 1 : 0);
  const confidence = totalSignals >= 3 ? "high" : totalSignals >= 2 ? "medium" : "low";

  const result = {
    score: Math.min(finalScore, 100),
    phishingScore: Math.min(finalPhishing, 100),
    piracyScore: Math.min(finalPiracy, 100),
    malwareScore: Math.min(finalMalware, 100),
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

  setCache(cacheKey, result);
  res.json(result);
});

// ── EMAIL SCAN ────────────────────────────────────────────────────
app.post("/scan/email", async (req, res) => {
  const { subject, sender, body } = req.body;
  console.log("[ShieldAI] Email scan:", subject?.slice(0, 40));

  const rules = rulesEmail(subject, sender, body);

  let aiResult = null;
  try {
    const aiText = await callAIText(
      `You are an email security expert. Analyze this email for phishing, scam, and social engineering.\n` +
      `Common attack vectors: fake login pages, credential harvesting, business email compromise, ` +
      `wire transfer fraud, malware delivery, fake package notifications.\n\n` +
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

  // Email scan: confidence based on distinct detection sources
  const totalEmailSignals = (rules.flags.length > 0 ? 1 : 0) + (aiResult ? 1 : 0);
  const confidence = totalEmailSignals >= 2 ? "high" : rules.flags.length > 0 ? "medium" : "low";

  res.json({
    score: Math.min(finalScore, 100),
    threat: finalScore >= 50,
    flags: finalFlags,
    verdict: aiResult?.verdict || (finalScore >= 50 ? "Phishing detected" : "Clean"),
    confidence
  });
});
app.post("/scan/code", async (req, res) => {
  const { code, filename } = req.body;
  console.log("[ShieldAI] Code scan:", filename || "inline");

  const rules = rulesMalcode(code, filename);

  let aiResult = null;
  try {
    const aiText = await callAIText(
      `You are a malware analyst. Analyze this code for malicious behavior.\n` +
      `Specifically check for: obfuscation techniques, data exfiltration (cookies, credentials, keystrokes), ` +
      `dropper/downloader patterns, keyloggers, cryptominers, cryptojackers, ` +
      `C2 communication, anti-debugging, hidden iframes, and unauthorized redirects.\n\n` +
      `Filename: ${filename || "unknown"}\n` +
      `Code: ${(code || "").slice(0, 1000)}\n` +
      `Rules pre-score: ${rules.score}\n\n` +
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

  // Code scan: confidence based on distinct detection sources
  const totalCodeSignals = (rules.flags.length > 0 ? 1 : 0) + (aiResult ? 1 : 0);
  const confidence = totalCodeSignals >= 2 ? "high" : rules.flags.length > 0 ? "medium" : "low";

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
