# 🔍 OSINT Toolkit

> ⚠️ **For authorized pentesting, CTF challenges, and ethical security research only.**

## Tools

### 1. `osint.py` — URL / Domain Intelligence
Analyzes a target URL and gathers:
- WHOIS info (registrar, owner, dates, emails)
- DNS records (A, MX, NS, TXT, CNAME, SOA)
- HTTP headers & tech stack detection
- Metadata & personal info extraction
- Password generation based on gathered data

**Usage:**
```bash
pip install python-whois dnspython
python osint.py https://target.com
```

---

### 2. `social_osint.py` — Social Media Profile Analyzer
Analyzes public social media profiles and generates targeted password candidates.

**Supported:** Instagram, Twitter/X, Facebook, LinkedIn, TikTok, GitHub, YouTube, Reddit

**Features:**
- Username tokenization & analysis
- Bio / description parsing (names, dates, locations)
- Personality trait analysis
- Smart password generation (leet-speak, suffixes, years)
- JSON report export

**Usage:**
```bash
python social_osint.py https://instagram.com/username
python social_osint.py https://twitter.com/username
python social_osint.py https://github.com/username
```

## Disclaimer
For authorized security assessments and CTF only.
