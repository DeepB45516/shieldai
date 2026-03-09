# ShieldAI — Complete Setup Guide

## Architecture

```
Firefox Extension
      ↓
  background.js
      ↓
  Your Node.js Backend  ← API key lives here (safe)
      ↓
  Claude AI + Google Safe Browsing + VirusTotal
```

---

## STEP 1 — Set Up the Backend

### Requirements
- Node.js installed (download from nodejs.org)

### Install & Run

```bash
# Open terminal, go to the backend folder
cd backend

# Install dependencies
npm install

# Add your API keys (edit server.js lines 8-10)
# OR set environment variables:

# Windows:
set CLAUDE_API_KEY=sk-ant-api03-YOUR_KEY
node server.js

# Mac/Linux:
CLAUDE_API_KEY=sk-ant-api03-YOUR_KEY node server.js
```

You should see:
```
✅ ShieldAI backend running on port 3000
   Claude key: ✓ configured
```

### Test it works
Open browser and go to: http://localhost:3000
You should see: `{"status":"ShieldAI backend running","version":"2.0"}`

---

## STEP 2 — Install the Firefox Extension

1. Open Firefox
2. Go to `about:debugging`
3. Click **This Firefox**
4. Click **Load Temporary Add-on**
5. Open the `extension` folder → select `manifest.json`
6. ShieldAI shield icon appears in toolbar ✓

---

## STEP 3 — Connect Extension to Backend

1. Click the ShieldAI shield icon in toolbar
2. In the **Backend URL** box at top, enter: `http://localhost:3000`
3. Click **PING** — it should turn green ✓
4. Now visit any website — it will be scanned automatically

---

## STEP 4 — Get Free API Keys (All Optional but Recommended)

### Claude AI (main AI engine)
- Go to: https://console.anthropic.com
- Create account → API Keys → Create Key
- Add to server.js line 8: `const CLAUDE_API_KEY = "sk-ant-..."`

### Google Safe Browsing (free, 10,000 req/day)
- Go to: https://console.cloud.google.com
- Enable "Safe Browsing API"
- Create credentials → API Key
- Add to server.js line 9: `const GOOGLE_SAFE_BROWSING_KEY = "AIza..."`

### VirusTotal (free, 4 req/min)
- Go to: https://virustotal.com → Sign up → Profile → API Key
- Add to server.js line 10: `const VIRUSTOTAL_KEY = "..."`

---

## STEP 5 — Deploy Backend Free Online (So Extension Works on Any Device)

### Option A: Render.com (easiest, free)
1. Go to render.com → Sign up
2. New → Web Service → Connect your GitHub repo
   (Or: New → Web Service → Deploy from a public Git URL)
3. Set environment variables in Render dashboard:
   - `CLAUDE_API_KEY` = your key
   - `GSB_KEY` = your Google key
   - `VT_KEY` = your VirusTotal key
4. Deploy → copy your URL like: `https://shieldai-xyz.onrender.com`
5. In extension popup, change Backend URL to your Render URL

### Option B: Railway.app (free tier)
1. Go to railway.app → New Project → Deploy from GitHub
2. Add environment variables
3. Copy the generated URL

### Option C: Keep running locally
Just keep `node server.js` running while using the extension.

---

## What Gets Detected

| Threat | Method |
|--------|--------|
| Phishing websites | URL rules + brand detection + Claude AI |
| Piracy sites | 60+ known domains database + keyword scan |
| Malicious JavaScript | 16 pattern rules + entropy analysis + Claude AI |
| Harmful downloads | Extension blocklist + VirusTotal API |
| Email phishing | Sender spoofing + urgency words + Claude AI |
| Suspicious images | Host + size + filename analysis |
| Known malware URLs | Google Safe Browsing API |

---

## Troubleshooting

**Extension shows "Backend offline"**
→ Make sure `node server.js` is running in terminal

**Backend runs but Claude not working**
→ Check your API key is correct in server.js

**Extension not scanning pages**
→ Go to about:debugging → click Inspect on ShieldAI → check Console tab

**Score always shows 0 or SAFE**
→ Click DEBUG tab in popup to see what's happening
