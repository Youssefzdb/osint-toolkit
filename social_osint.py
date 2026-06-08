#!/usr/bin/env python3
"""
Social Media OSINT Tool
Analyzes public social media profiles and generates targeted passwords
For authorized security testing and CTF only.
"""

import sys
import re
import json
import time
import urllib.request
import urllib.parse
from datetime import datetime

# ─────────────────────────────────────────────
LEET_MAP = {'a':'4','e':'3','i':'1','o':'0','s':'5','t':'7','b':'8','g':'9'}

def leet(word):
    return ''.join(LEET_MAP.get(c.lower(), c) for c in word)

def print_section(title):
    print(f"\n{'═'*58}")
    print(f"  🔍 {title}")
    print(f"{'═'*58}")

def safe_get(url, timeout=10, extra_headers=None):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if extra_headers:
        headers.update(extra_headers)
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return None

# ─────────────────────────────────────────────
# PLATFORM DETECTORS
# ─────────────────────────────────────────────

def detect_platform(url):
    platforms = {
        "instagram": r"instagram\.com",
        "twitter":   r"twitter\.com|x\.com",
        "facebook":  r"facebook\.com|fb\.com",
        "linkedin":  r"linkedin\.com",
        "tiktok":    r"tiktok\.com",
        "github":    r"github\.com",
        "youtube":   r"youtube\.com",
        "reddit":    r"reddit\.com",
        "pinterest": r"pinterest\.com",
        "snapchat":  r"snapchat\.com",
    }
    for name, pat in platforms.items():
        if re.search(pat, url, re.IGNORECASE):
            return name
    return "unknown"

def extract_username(url, platform):
    patterns = {
        "instagram": r"instagram\.com/([A-Za-z0-9_\.]{1,60})",
        "twitter":   r"(?:twitter|x)\.com/([A-Za-z0-9_]{1,50})",
        "facebook":  r"facebook\.com/([A-Za-z0-9\.]{1,80})",
        "linkedin":  r"linkedin\.com/in/([A-Za-z0-9\-]{1,80})",
        "tiktok":    r"tiktok\.com/@?([A-Za-z0-9_\.]{1,50})",
        "github":    r"github\.com/([A-Za-z0-9\-]{1,40})",
        "youtube":   r"youtube\.com/(?:c/|channel/|user/|@)?([A-Za-z0-9_\-\.]{1,80})",
        "reddit":    r"reddit\.com/u(?:ser)?/([A-Za-z0-9_\-]{1,50})",
        "pinterest": r"pinterest\.com/([A-Za-z0-9_]{1,50})",
    }
    pat = patterns.get(platform)
    if pat:
        m = re.search(pat, url, re.IGNORECASE)
        if m:
            return m.group(1).strip("/")
    return url.rstrip("/").split("/")[-1]

# ─────────────────────────────────────────────
# SCRAPERS PER PLATFORM
# ─────────────────────────────────────────────

def scrape_generic(url, platform, username):
    """Generic HTML scraper — works for public profiles."""
    body = safe_get(url)
    if not body:
        body = safe_get("http://" + url.replace("https://","").replace("http://",""))
    return body or ""

def parse_profile_data(body, platform, username):
    """Extract personal info tokens from HTML body."""
    data = {"username": username, "platform": platform, "tokens": set(), "raw": {}}

    if not body:
        return data

    # Full name patterns
    name_patterns = [
        r'"full_name"\s*:\s*"([^"]{2,60})"',
        r'"name"\s*:\s*"([A-Z][a-z]+ [A-Z][a-z]+[^"]{0,40})"',
        r'<title>([^<]{5,80})\s*[|\-–]',
        r'itemprop="name"[^>]*>([^<]{3,60})<',
        r'class="[^"]*name[^"]*"[^>]*>([A-Z][a-z]+ [A-Z][a-z]+)',
        r'og:title" content="([^"]{3,60})"',
    ]
    for pat in name_patterns:
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            name = m.group(1).strip()
            if name and name.lower() not in ("instagram","twitter","facebook","tiktok","youtube"):
                data["raw"]["full_name"] = name
                for part in name.split():
                    if len(part) > 2:
                        data["tokens"].add(part.lower())
                data["tokens"].add(name.replace(" ","").lower())
                break

    # Bio / description
    bio_patterns = [
        r'"biography"\s*:\s*"([^"]{5,300})"',
        r'"description"\s*:\s*"([^"]{5,300})"',
        r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']',
        r'og:description" content="([^"]{5,300})"',
    ]
    for pat in bio_patterns:
        m = re.search(pat, body, re.IGNORECASE | re.DOTALL)
        if m:
            bio = m.group(1).strip()
            data["raw"]["bio"] = bio[:300]
            # extract words from bio
            words = re.findall(r'[A-Za-z\u0600-\u06FF]{3,15}', bio)
            for w in words[:20]:
                data["tokens"].add(w.lower())
            # dates in bio
            dates = re.findall(r'\b(19[5-9]\d|20[0-2]\d)\b', bio)
            data["raw"].setdefault("years", []).extend(dates)
            # numbers that look like birth dates
            date_patterns = re.findall(r'\b(\d{1,2})[/\-\.](\d{1,2})[/\-\.](\d{2,4})\b', bio)
            for d in date_patterns:
                data["raw"].setdefault("dates_raw", []).append("/".join(d))
            break

    # Emails
    emails = list(set(re.findall(r'[\w\.-]+@[\w\.-]+\.\w{2,6}', body)))
    if emails:
        data["raw"]["emails"] = emails[:5]
        for e in emails[:3]:
            local = e.split("@")[0]
            for part in re.split(r'[._\-]', local):
                if len(part) > 2:
                    data["tokens"].add(part.lower())

    # Phone numbers
    phones = list(set(re.findall(r'[\+\(]?[\d\s\-\(\)]{8,18}[\d]', body)))
    phones = [re.sub(r'\s','',p) for p in phones if len(re.sub(r'\D','',p)) >= 7][:5]
    if phones:
        data["raw"]["phones"] = phones

    # Website / linked URLs
    websites = re.findall(r'https?://(?!(?:instagram|twitter|facebook|x\.|tiktok|youtube))[^\s"\'<>]{5,60}', body)
    if websites:
        data["raw"]["linked_sites"] = list(set(websites))[:5]

    # Location
    loc_patterns = [
        r'"location"\s*:\s*"([^"]{2,60})"',
        r'class="[^"]*location[^"]*"[^>]*>([^<]{3,50})<',
    ]
    for pat in loc_patterns:
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            loc = m.group(1).strip()
            data["raw"]["location"] = loc
            for part in loc.split():
                if len(part) > 3:
                    data["tokens"].add(part.lower())
            break

    # Years from anywhere
    years = list(set(re.findall(r'\b(19[5-9]\d|20[0-2]\d)\b', body)))
    data["raw"].setdefault("years", [])
    data["raw"]["years"] = list(set(data["raw"]["years"] + years))[:10]

    # Pet names (common pattern: "my dog X", "my cat X")
    pet = re.findall(r'(?:my |our )(?:dog|cat|pet|baby|son|daughter|wife|husband)\s+([A-Z][a-z]{2,15})', body)
    if pet:
        data["raw"]["pet_names"] = list(set(pet))[:3]
        for p in pet[:3]:
            data["tokens"].add(p.lower())

    # Numeric sequences from username
    nums = re.findall(r'\d+', username)
    data["raw"]["username_numbers"] = nums

    # username itself as token
    data["tokens"].add(username.lower())
    # split username by common separators
    for part in re.split(r'[._\-]', username):
        if len(part) > 2:
            data["tokens"].add(part.lower())

    return data

# ─────────────────────────────────────────────
# PERSONALITY ANALYSIS
# ─────────────────────────────────────────────

def analyze_personality(data):
    print_section("PERSONALITY ANALYSIS")
    bio = data["raw"].get("bio","")
    username = data["username"]
    tokens = data["tokens"]

    traits = []

    # Numerics in username → tech-savvy or gamer
    if re.search(r'\d{2,}', username):
        traits.append("🎮 Uses numbers in username — possibly birth year or gamer tag")
    # underscores
    if "_" in username:
        traits.append("🔧 Uses underscores — common in tech/developer circles")
    # dots
    if "." in username:
        traits.append("👔 Uses dots — professional naming style (e.g. firstname.lastname)")
    # all lowercase
    if username == username.lower() and not re.search(r'\d', username):
        traits.append("😎 All lowercase username — casual/minimalist style")
    # camelCase
    if re.search(r'[a-z][A-Z]', username):
        traits.append("💻 CamelCase username — developer/tech background likely")

    if bio:
        bio_lower = bio.lower()
        # Religion
        if re.search(r'allah|islam|muslim|قرآن|الله|ماشاء|بسم|الحمد', bio_lower):
            traits.append("🕌 Religious keywords in bio — likely uses religious references in passwords")
        # Family
        if re.search(r'father|mother|dad|mom|family|husband|wife|أب|أم|زوج|زوجة|عائلة', bio_lower):
            traits.append("👨‍👩‍👧 Family-oriented — may use family member names in passwords")
        # Sports
        if re.search(r'football|soccer|sport|gym|fitness|كرة|رياضة', bio_lower):
            traits.append("⚽ Sports enthusiast — may use team names or sport terms")
        # Tech
        if re.search(r'developer|engineer|coder|programmer|tech|cyber|هندسة|مطور|برمجة', bio_lower):
            traits.append("💻 Tech/developer profile — likely uses complex or leet-speak passwords")
        # Location pride
        if re.search(r'proud|from|born in|tunisia|morocco|egypt|algeria|مصر|تونس|الجزائر|المغرب', bio_lower):
            traits.append("🌍 Location pride — city/country name likely in password")
        # Love interest / relationship
        if re.search(r'love|❤|💕|💙|forever|always', bio_lower):
            traits.append("💕 Romantic expressions — may use partner name or anniversary date")

    for t in traits:
        print(f"  {t}")
    if not traits:
        print("  ℹ️  Not enough public info for deep personality analysis.")

    return traits

# ─────────────────────────────────────────────
# PASSWORD GENERATOR
# ─────────────────────────────────────────────

def generate_passwords(data, traits):
    print_section("GENERATED PASSWORD CANDIDATES")

    tokens   = list(data["tokens"])
    years    = data["raw"].get("years", [])
    phones   = data["raw"].get("phones", [])
    username = data["username"]
    nums_in_user = data["raw"].get("username_numbers", [])

    suffixes = [
        "", "123", "1234", "12345", "!", "@", "#", ".", "_",
        "2024", "2025", "2023", "01", "99", "00", "007", "786",
        "!@#", "*", "$$",
    ]
    specials = ["!", "@", "#", "_", ".", "*", "786", "1"]

    passwords = set()

    # — Token-based —
    for tok in tokens[:18]:
        cap = tok.capitalize()
        for suf in suffixes[:12]:
            passwords.add(tok + suf)
            passwords.add(cap + suf)
            passwords.add(leet(tok) + suf)
        for yr in years[:4]:
            passwords.add(tok + yr)
            passwords.add(cap + yr)
            passwords.add(tok + yr + "!")
            passwords.add(cap + yr + "@")
        for n in nums_in_user[:2]:
            passwords.add(tok + n)
            passwords.add(cap + n)

    # — Username combos —
    passwords.add(username)
    passwords.add(username + "123")
    passwords.add(username + "!")
    passwords.add(username.capitalize())
    for yr in years[:3]:
        passwords.add(username + yr)
    for suf in ["_123","_2024","_2025","01","99"]:
        passwords.add(username + suf)

    # — Phone number fragments —
    for ph in phones[:2]:
        digits = re.sub(r'\D','',ph)
        if len(digits) >= 8:
            passwords.add(digits[-8:])
            passwords.add(digits[-4:])
            for tok in list(tokens)[:5]:
                passwords.add(tok + digits[-4:])
                passwords.add(tok.capitalize() + digits[-4:])

    # — Token pairs (name + year / name + name) —
    if len(tokens) >= 2:
        t1, t2 = list(tokens)[0], list(tokens)[1]
        passwords.add(t1 + t2)
        passwords.add(t1.capitalize() + t2.capitalize())
        passwords.add(t1 + t2 + "123")
        passwords.add(t1.capitalize() + t2 + "!")
        for yr in years[:2]:
            passwords.add(t1 + t2 + yr)

    # — Trait-based additions —
    for trait in traits:
        if "Religious" in trait or "allah" in trait.lower():
            for tok in list(tokens)[:5]:
                passwords.add(tok + "786")
                passwords.add(tok.capitalize() + "786")
                passwords.add("Allah" + tok.capitalize())
        if "Sports" in trait:
            for sport in ["goal","sport","fc","real","united"]:
                for tok in list(tokens)[:3]:
                    passwords.add(tok + sport)
        if "Tech" in trait or "developer" in trait.lower():
            for tok in list(tokens)[:5]:
                passwords.add(leet(tok) + "!")
                passwords.add(tok + "@123")
                passwords.add("admin" + tok.capitalize())

    # clean & sort
    final = sorted(
        {p for p in passwords if 6 <= len(p) <= 30},
        key=lambda x: -len(x)
    )[:60]

    print(f"\n  ✅ Generated {len(final)} password candidates:\n")
    for i, pw in enumerate(final, 1):
        print(f"  {i:3}. {pw}")

    return final

# ─────────────────────────────────────────────
# EXPORT
# ─────────────────────────────────────────────

def export_report(url, platform, data, traits, passwords):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"social_osint_{platform}_{data['username']}_{ts}.json"
    report = {
        "target_url":  url,
        "platform":    platform,
        "username":    data["username"],
        "date":        datetime.now().isoformat(),
        "extracted":   {k: list(v) if isinstance(v, set) else v for k, v in data["raw"].items()},
        "tokens":      list(data["tokens"]),
        "traits":      traits,
        "passwords":   passwords,
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n  💾 Report saved → {filename}")
    return filename

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print("╔══════════════════════════════════════════════════════════╗")
    print("║       SOCIAL MEDIA OSINT TOOL — Password Generator       ║")
    print("║       ⚠️  For authorized pentesting & CTF only ⚠️          ║")
    print("╚══════════════════════════════════════════════════════════╝")

    if len(sys.argv) > 1:
        url = sys.argv[1].strip()
    else:
        url = input("\n  [?] Enter Social Media Profile URL: ").strip()

    if not url.startswith("http"):
        url = "https://" + url

    platform = detect_platform(url)
    username = extract_username(url, platform)

    print(f"\n  🎯 Target    : {url}")
    print(f"  📱 Platform  : {platform.upper()}")
    print(f"  👤 Username  : {username}")
    print(f"  🕐 Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    print_section("FETCHING PROFILE DATA")
    print("  Scraping public profile...")
    body = scrape_generic(url, platform, username)

    if body:
        print(f"  ✅ Got {len(body):,} bytes of data")
    else:
        print("  ⚠️  Could not fetch page — profile may be private or protected.")
        print("  ℹ️  Continuing with username-based analysis only...\n")

    data = parse_profile_data(body, platform, username)

    print_section("EXTRACTED INFORMATION")
    for key, val in data["raw"].items():
        display = val if not isinstance(val, list) else ", ".join(val[:5])
        print(f"  {key:20}: {str(display)[:100]}")
    print(f"  {'tokens':20}: {', '.join(list(data['tokens'])[:15])}")

    traits    = analyze_personality(data)
    passwords = generate_passwords(data, traits)
    report    = export_report(url, platform, data, traits, passwords)

    print(f"\n{'═'*58}")
    print(f"  ✅ Scan complete! Report: {report}")
    print(f"{'═'*58}\n")

if __name__ == "__main__":
    main()
