import re
from urllib.parse import urlparse

# Known URL shorteners

KNOWN_SHORTENERS = (
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "short.io", "cutt.ly",
    "bl.ink", "tiny.cc", "shorte.st",
)


SUSPICIOUS_TLDS = (
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".click", ".link", ".online", ".site", ".info",
)


def extract_features(url: str) -> dict:
    """Return feature dict only (no reasons)."""
    features, _ = extract_features_with_reasons(url)
    return features


def extract_features_with_reasons(url: str) -> tuple[dict, list]:
    
    parsed  = urlparse(url)
    domain  = parsed.netloc.lower()
    scheme  = parsed.scheme.lower()
    path_q  = f"{parsed.path.lower()}?{parsed.query.lower()}"
    reasons = []

    # 1. IP address as domain
    has_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", domain))

    # 2. URL length  (<54 = safe, 54-75 = suspicious, >75 = phishing)
    url_len = len(url)
    url_length_score = 1 if url_len < 54 else (0 if url_len <= 75 else -1)

    # 3. URL shortening service
    is_shortened = any(s in domain for s in KNOWN_SHORTENERS)

    # 4. @ symbol tricks browsers into ignoring everything before it
    has_at = "@" in url

    # 5. Double-slash redirect after the protocol
    after_proto      = url[url.find("://") + 3:] if "://" in url else url
    has_double_slash = "//" in after_proto

    # 6. Hyphen in domain (prefix-suffix spoofing)
    has_hyphen = "-" in domain.split("/")[0]

    # 7. Subdomain depth
    clean_domain    = re.sub(r"^www\.", "", domain.split(":")[0])
    dot_count       = clean_domain.count(".")
    subdomain_score = 1 if dot_count <= 1 else (0 if dot_count == 2 else -1)

    # 8. HTTPS scheme
    is_https = scheme == "https"

    # 9. "https" token embedded in domain name (fake trust signal)
    https_in_domain = "https" in domain.replace("www.", "")

    # 10. mailto: in path/query (form submits to email)
    has_mailto = "mailto:" in path_q

    # 11. Suspicious TLD
    has_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)

    # 12. Abnormal URL (domain string not found in full URL — edge case)
    abnormal = bool(domain and domain not in url)

    # 13. Multiple redirect patterns in path
    redirect_count = path_q.count("//")


    features = {
        "having_IP_Address":           -1 if has_ip else 1,
        "URL_Length":                  url_length_score,
        "Shortining_Service":          -1 if is_shortened else 1,
        "having_At_Symbol":            -1 if has_at else 1,
        "double_slash_redirecting":    -1 if has_double_slash else 1,
        "Prefix_Suffix":               -1 if has_hyphen else 1,
        "having_Sub_Domain":           subdomain_score,
        "SSLfinal_State":              1 if is_https else -1,
        "Domain_registeration_length": 0,   # requires WHOIS lookup
        "Favicon":                     0,   # requires page fetch
        "port":                        0,   # requires port scan
        "HTTPS_token":                 -1 if https_in_domain else 1,
        "Request_URL":                 0,
        "URL_of_Anchor":               0,
        "Links_in_tags":               0,
        "SFH":                         0,
        "Submitting_to_email":         -1 if has_mailto else 1,
        "Abnormal_URL":                -1 if abnormal else 1,
        "Redirect":                    -1 if redirect_count > 1 else 1,
        "on_mouseover":                0,
        "RightClick":                  0,
        "popUpWidnow":                 0,
        "Iframe":                      0,
        "age_of_domain":               0,
        "DNSRecord":                   0,
        "web_traffic":                 0,
        "Page_Rank":                   0,
        "Google_Index":                0,
        "Links_pointing_to_page":      0,
        "Statistical_report":          0,
    }

    # Reasons list

    if has_ip:              reasons.append("Domain uses direct IP address")
    if url_length_score==-1:reasons.append("Very long URL")
    if is_shortened:        reasons.append("URL shortener detected")
    if has_at:              reasons.append("Contains '@' symbol in URL")
    if has_double_slash:    reasons.append("Has suspicious double-slash redirect")
    if has_hyphen:          reasons.append("Domain contains '-' pattern")
    if subdomain_score==-1: reasons.append("Too many subdomains")
    if not is_https:        reasons.append("Not using HTTPS")
    if https_in_domain:     reasons.append("Suspicious 'https' token in domain")
    if has_mailto:          reasons.append("Page appears to submit data through email")
    if has_suspicious_tld:  reasons.append("Suspicious top-level domain (TLD) detected")
    if redirect_count > 1:  reasons.append("Multiple redirect patterns in URL path")

    return features, reasons
