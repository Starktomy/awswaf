import time

from awswaf.aws import AwsWaf
from curl_cffi import requests
from concurrent.futures import ThreadPoolExecutor

# Test sites
TEST_SITES = [
    ("binance", "https://www.binance.com/"),
    ("thumbtack", "https://www.thumbtack.com/"),
    ("sothebysrealty", "https://www.sothebysrealty.com/"),
    # ("officeworks", "https://www.officeworks.com.au/"),  # Uses captcha, not mp_verify
]

def solve_site(name, url):
    """Solve WAF challenge for a single site"""
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
        print(f"[-] {name}: Connection error - {e}")
        return False

    # Check if WAF challenge is present
    if response.status_code != 202 and 'gokuProps' not in response.text:
        # No challenge, site might not have WAF or already accessible
        print(f"[?] {name}: No WAF challenge detected (status={response.status_code})")
        return True

    try:
        goku, host = AwsWaf.extract(response.text)
    except Exception as e:
        print(f"[-] {name}: Failed to extract goku props - {e}")
        return False

    # Pass session to AwsWaf so it uses the same session
    domain = url.split("//")[1].split("/")[0]
    awswaf = AwsWaf(goku, host, domain, session=session)

    start = time.time()
    try:
        token = awswaf()
    except Exception as e:
        print(f"[-] {name}: Failed to solve - {e}")
        return False
    end = time.time()

    # Set cookie for test request
    session.cookies.set("aws-waf-token", token)

    # Test access
    test_resp = session.get(url)

    if test_resp.headers.get('x-amzn-waf-action') != 'challenge' and len(test_resp.text) > 5000:
        print(f"[+] {name}: Solved in {str(end - start)[:6]}s (page: {len(test_resp.text)} bytes)")
        return True
    else:
        print(f"[-] {name}: Failed (waf: {test_resp.headers.get('x-amzn-waf-action')}, len: {len(test_resp.text)})")
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
