# URL Safety Chatbot 🛡️

Paste any link and get a clear verdict: **Likely Safe / Suspicious / Dangerous**, plus an explanation.

## Features
- URL validation & domain extraction
- DNS lookups (A/AAAA/MX/NS)
- WHOIS (domain age, registrar, expiry)
- HTTPS/SSL certificate inspection
- Google Safe Browsing (optional API)
- VirusTotal (optional API)
- Wayback Machine history check
- Chat-style UI (Streamlit)

## Install & Run
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Environment Variables (optional)
Create a `.env` file in the project folder:
```
GOOGLE_SAFE_BROWSING_API_KEY=your_gsb_key
VT_API_KEY=your_virustotal_key
PHISHTANK_API_KEY=your_phishtank_key   # (not used yet in code, reserved)
```

## Notes
- Heuristic risk score is **not** a guarantee. Combine signals + human judgment.
- Some lookups (WHOIS/DNS/SSL) may take a few seconds and depend on network access.
- VirusTotal scan may take ~10–15 seconds as it queues and processes the URL.

## Roadmap
- Add PhishTank/OpenPhish feeds
- Screenshot preview via urlscan.io
- Brand impersonation detection
- Model-based URL classifier (scikit-learn)
