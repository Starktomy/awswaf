import os
import time

from awswaf.aws import AwsWaf
from awswaf.captcha_solver import solve_with_playwright
from curl_cffi import requests

# Test sites
TEST_SITES = [
    # mp_verify challenge
    ("binance.com", "https://www.binance.com/"),
    ("kaikoura.govt.nz", "https://www.kaikoura.govt.nz/"),
    ("cppinvestments.com", "https://www.cppinvestments.com/"),
    # CAPTCHA challenge (solved with vision model)
    ("telaambientes.com.br", "https://telaambientes.com.br/"),
    # mp_verify with www redirect
    ("daybrookmedicalpractice.co.uk", "https://daybrookmedicalpractice.co.uk/"),
    ("thebushdoctors.co.uk", "https://thebushdoctors.co.uk/"),
    ("swanlowmedicalcentre.co.uk", "https://swanlowmedicalcentre.co.uk/"),
]


def solve_site(name, url):
    """Solve WAF challenge for a single site"""
    # Try original URL first, then try with www prefix
    result = solve_site_with_url(name, url) or solve_site_with_url(name, url.replace("https://", "https://www."))

    # If mp_verify fails, try CAPTCHA solver
    if not result:
        result = solve_captcha(url)

    return result


def solve_captcha(url, api_key=None):
    """Solve CAPTCHA challenge using Playwright + vision model"""
    if api_key is None:
        api_key = os.environ.get('DASHSCOPE_API_KEY')
        if not api_key:
            print("  [-] No DASHSCOPE_API_KEY set")
            return False

    try:
        return solve_with_playwright(url, api_key)
    except Exception as e:
        print(f"  [-] CAPTCHA solver error: {e}")
        return False


def solve_site_with_url(name, url):
    """Solve WAF challenge for a single site with specific URL"""
    session = requests.Session(impersonate="chrome")

    session.headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.5',
        'cache-control': 'no-cache',
        'pragma': 'no-cache',
        'priority': 'u=0, i',
        'sec-ch-ua': '"Chromium";v="136", "Brave";v="136", "Not.A/Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'sec-gpc': '1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    }

    try:
        response = session.get(url)
    except Exception as e:
        return False

    # Check if page loaded directly (no challenge)
    if 'gokuProps' not in response.text:
        # No WAF challenge - page loaded directly
        if response.status_code == 200 and len(response.text) > 5000:
            print(f"[+] {name}: No challenge (page: {len(response.text)} bytes)")
            return True
        return False

    try:
        goku, host = AwsWaf.extract(response.text)
    except Exception as e:
        return False

    # Pass session to AwsWaf so it uses the same session
    domain = url.split("//")[1].split("/")[0]
    awswaf = AwsWaf(goku, host, domain, session=session)

    start = time.time()
    try:
        token = awswaf()
    except Exception as e:
        return False
    end = time.time()

    # Set cookie for test request
    session.cookies.set("aws-waf-token", token)

    # Test access
    test_resp = session.get(url)

    if test_resp.headers.get('x-amzn-waf-action') != 'challenge' and len(test_resp.text) > 5000:
        print(f"[+] {name}: mp_verify solved in {str(end - start)[:6]}s (page: {len(test_resp.text)} bytes)")
        return True
    else:
        return False


def solve():
    """Test all sites"""
    print("=" * 50)
    print("AWS WAF mp_verify Challenge Solver Test")
    print("=" * 50)

    results = []
    for name, url in TEST_SITES:
        print(f"\n[*] Testing: {name} ({url})")
        result = solve_site(name, url)
        results.append((name, result))

    print("\n" + "=" * 50)
    print("Results:")
    print("=" * 50)
    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"  [{status}] {name}")

    passed = sum(1 for _, r in results if r)
    print(f"\nTotal: {passed}/{len(results)} passed")


if __name__ == "__main__":
    solve()
