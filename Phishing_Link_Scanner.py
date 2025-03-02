import re
import tldextract
from urllib.parse import urlparse

# List of common phishing domains (this can be extended by using a more comprehensive list)
PHISHING_DOMAINS = ['.top', '.xyz', '.club', '.date', '.pw', '.win', '.gq']

# List of common phishing keywords (for demonstration purposes)
PHISHING_KEYWORDS = ["login", "verify", "account", "update", "secure", "alert", "password", "signin",
                     "confirm", "claim", "reward", "refund", "payment"]

# Validate the URL format.
def is_valid_url(url):
    # Add "https://" if the URL starts with "www"
    if url.lower().startswith("www"):
        url = "https://" + url
    url_pattern = re.compile(
        r'^(?:http|ftp)s?://' or r'www\d{0,3}[.]?'  #https:// or www.
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(url_pattern, url) is not None

# Check if the URL uses HTTPS
def is_https(url):
    return url.lower().startswith("https://") or url.lower().startswith("www")

# Check if the domain is from a suspicious list
def is_suspicious_domain(domain):
    for suffix in PHISHING_DOMAINS:
        if domain.endswith(suffix):
            return True
    return False

# Check for 'www' in URL
def check_www_in_url(url):
    parsed_url = urlparse(url)
    netloc = parsed_url.netloc
    if netloc.startswith("www"):
        www_part = netloc.split('.')[0]
        if len(www_part) != 3:
            print("Invalid URL")
            return False
    return True

# Check for suspicious subdomains
def has_suspicious_subdomains(url):
    extracted = tldextract.extract(url)
    subdomain_count = len(extracted.subdomain.split('.'))
    return subdomain_count > 2

# Check for a valid domain (not using an IP address)
def is_valid_domain(url):
    parsed_url = urlparse(url)
    return not parsed_url.netloc.replace('.', '').isdigit()  # Check if domain is an IP address

# Check if the domain contains phishing keywords
def contains_phishing_keywords(domain):
    for keyword in PHISHING_KEYWORDS:
        if keyword in domain:
            return True
    return False

# Check for special symbols between subdomain and domain
def has_special_symbols(url):
    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain
    domain = extracted.domain
    combined = subdomain + domain
    return any(char in combined for char in ['-', '_', '%', '@', '!', '~', '?'])

# Check for multiple dots or dots in unexpected places
def has_multiple_dots_or_unexpected_dot(url):
    extracted = tldextract.extract(url)
    domain_parts = extracted.domain.split('.')
    subdomain_parts = extracted.subdomain.split('.')
    
    # Check for multiple dots in domain or subdomain
    if len(domain_parts) > 1 or any(len(part) == 1 for part in domain_parts + subdomain_parts):
        return True
    
    # Check for dot after domain extension
    parsed_url = urlparse(url)
    path = parsed_url.path
    if path.startswith('.'):
        return True
    
    return False

# Scan the URL
def scan_url(url):
    print(f"Scanning URL: {url}")
    
    # Check if the URL uses HTTPS
    if not is_https(url):
        print("Suspicious: The URL does not use HTTPS.")
        return "Suspicious"
    
    # Check for suspicious subdomains
    if has_suspicious_subdomains(url):
        print("Suspicious: The URL has too many subdomains.")
        return "Suspicious"
    
    # Check if the domain is valid (not an IP address)
    if not is_valid_domain(url):
        print("Suspicious: The URL seems to use an IP address instead of a domain.")
        return "Suspicious"
    
    # Check if the URL contains suspicious domains
    extracted = tldextract.extract(url)
    domain = extracted.domain + '.' + extracted.suffix
    if is_suspicious_domain(domain):
        print(f"Suspicious: Domain {domain} is blacklisted.")
        return "Suspicious"
    
    # Check if the domain contains phishing keywords
    if contains_phishing_keywords(domain):
        print(f"Suspicious: Domain {domain} contains phishing keywords.")
        return "Suspicious"
    
    # Check for special symbols between subdomain and domain
    if has_special_symbols(url):
        print("Suspicious: The URL contains special symbols.")
        return "Suspicious"
    
    # Check for multiple dots or dots in unexpected places
    if has_multiple_dots_or_unexpected_dot(url):
        print("Suspicious: The URL contains multiple dots or dots in unexpected places.")
        return "Suspicious"
    
    # Check for 'www' in URL
    if not check_www_in_url(url):
        return "Suspicious"
    
    print("The URL seems to be safe.")
    return "Safe"

# Test the scanner with a list of URLs
if __name__ == "__main__":
    url = input("Enter a URL to scan: ")
    if is_valid_url(url):
        result = scan_url(url)
        print(f"Result for {url}: {result}\n")
    else:
        print("Invalid URL format")