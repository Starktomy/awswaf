import time

from awswaf.aws import AwsWaf
from curl_cffi import requests
from concurrent.futures import ThreadPoolExecutor

def solve():
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
    response = session.get("https://www.binance.com/")
    goku, host = AwsWaf.extract(response.text)

    # Pass session to AwsWaf so it uses the same session
    awswaf = AwsWaf(goku, host, "www.binance.com", session=session)

    start = time.time()
    token = awswaf()
    end = time.time()

    # Set cookie for test request
    session.cookies.set("aws-waf-token", token)

    # Test access
    test_resp = session.get("https://www.binance.com/")

    if test_resp.headers.get('x-amzn-waf-action') != 'challenge' and len(test_resp.text) > 20000:
        print("[+] Solved:", token, "in", str(end - start) + "s")
        print("[+] Page length:", len(test_resp.text))
    else:
        print("failed to solve!")
        print("Response length:", len(test_resp.text))
        print("WAF action:", test_resp.headers.get('x-amzn-waf-action'))


if __name__ == "__main__":
    solve()
