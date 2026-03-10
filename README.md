# ShieldAI — Complete Setup Guide

## Architecture

```
Firefox Extension
      ↓
  background.js
      ↓
  Your Node.js Backend  ← runs all AI locally (no API keys needed)
      ↓
  Local AI Models (Transformers.js) + Google Safe Browsing + VirusTotal
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

# Add your API keys (edit server.js lines 15-17)
# OR set environment variables:

# Windows:
set GSB_KEY=YOUR_GOOGLE_SAFE_BROWSING_KEY
node server.js

# Mac/Linux:
GSB_KEY=YOUR_GOOGLE_SAFE_BROWSING_KEY node server.js
```

You should see:
```
✅ ShieldAI backend running on port 3000
   GSB key: ✗ not set (optional)
   VT key:  ✗ not set (optional)
⏳ Loading local AI models...
✅ Local AI models loaded
```

### Test it works
Open browser and go to: http://localhost:3000
You should see: `{"status":"ShieldAI backend running","version":"3.0"}`

Check model status: http://localhost:3000/health

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

### Google Safe Browsing (free, 10,000 req/day)
- Go to: https://console.cloud.google.com
- Enable "Safe Browsing API"
- Create credentials → API Key
- Set env var: `GSB_KEY=AIza...`

### VirusTotal (free, 4 req/min)
- Go to: https://virustotal.com → Sign up → Profile → API Key
- Set env var: `VT_KEY=...`

---

## STEP 5 — Deploy Backend Free Online (So Extension Works on Any Device)

### Option A: Render.com (easiest, free)
1. Go to render.com → Sign up
2. New → Web Service → Connect your GitHub repo
   (Or: New → Web Service → Deploy from a public Git URL)
3. Set environment variables in Render dashboard:
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
| Phishing websites | URL rules + brand detection + AI (`nli-deberta-v3-small`) |
| Piracy sites | 150+ known domains + content fingerprinting + AI zero-shot |
| Malicious JavaScript | 16+ pattern rules + entropy analysis + AI |
| Harmful downloads | Extension blocklist + VirusTotal API |
| Email phishing | Sender spoofing + urgency words + AI + sentiment analysis |
| AI-generated images | URL heuristics + CLIP zero-shot + ViT + deepfake detection |
| Known malware URLs | Google Safe Browsing API |

---

## AI Models Used (100% Free & Local, Never Expire)

All models run locally via `@xenova/transformers` — no API keys, no cost, no expiration.
Models are downloaded once and cached automatically (~650MB total: DeBERTa ~150MB, CLIP ~350MB, DistilBERT ~67MB, ViT ~86MB).

| Model | Purpose | Notes |
|-------|---------|-------|
| `Xenova/nli-deberta-v3-small` | Zero-shot classification (phishing, piracy, malware) | Primary; falls back to distilbart-mnli-12-3, then mobilebert |
| `Xenova/clip-vit-base-patch32` | Zero-shot image-text matching for AI image detection | Directly asks "Is this AI generated?" |
| `Xenova/distilbert-base-uncased-finetuned-sst-2-english` | Sentiment analysis for email phishing | Phishing emails are highly negative/fear-inducing |
| `Xenova/vit-base-patch16-224` | Image content metadata (secondary signal) | Kept as supporting signal |

---

## Troubleshooting

**Extension shows "Backend offline"**
→ Make sure `node server.js` is running in terminal

**Models slow to load on first run**
→ Models are downloaded and cached on first use (~650MB total). Subsequent starts are fast.

**Extension not scanning pages**
→ Go to about:debugging → click Inspect on ShieldAI → check Console tab

**Score always shows 0 or SAFE**
→ Click DEBUG tab in popup to see what's happening
