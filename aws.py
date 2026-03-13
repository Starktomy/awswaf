import random, json

from curl_cffi import requests
from awswaf.verify import CHALLENGE_TYPES
from awswaf.fingerprint import get_fp


class AwsWaf:
    def __init__(self, goku_props: str,
                 endpoint: str,
                 domain: str,
                 user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
                 session=None,
                 ):
        if session is not None:
            self.session = session
        else:
            self.session = requests.Session(impersonate="chrome")
            self.session.headers = {
                "connection": "keep-alive",
                "sec-ch-ua-platform": "\"Windows\"",
                "user-agent": user_agent,
                "sec-ch-ua": "\"Chromium\";v=\"136\", \"Google Chrome\";v=\"136\", \"Not.A/Brand\";v=\"99\"",
                "sec-ch-ua-mobile": "?0",
                "accept": "*/*",
                #"origin": "https://www.binance.com",
                "sec-fetch-site": "cross-site",
                "sec-fetch-mode": "cors",
                "sec-fetch-dest": "empty",
                #"referer": "https://www.binance.com/",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "en-US,en;q=0.9"
            }
        self.goku_props = goku_props
        self.user_agent = user_agent
        self.domain = domain
        self.endpoint = endpoint

    @staticmethod
    def extract(html: str):
        goku_props = json.loads(html.split("window.gokuProps = ")[1].split(";")[0])
        host = html.split("src=\"https://")[1].split("/challenge.js")[0]
        return goku_props, host

    def get_inputs(self):
        return self.session.get(
            f"https://{self.endpoint}/inputs?client=browser").json()

    def build_payload(self, inputs: dict):
        challenge_type = inputs["challenge_type"]
        verify = CHALLENGE_TYPES.get(challenge_type)
        checksum, fp = get_fp(self.user_agent)

        # Handle mp_verify challenge type
        if challenge_type == "mp_verify" or verify == "mp_verify":
            import base64
            # mp_verify uses multipart/form-data with solution_data
            solution_data = base64.b64encode(b'\x00' * 1024).decode('utf-8')
            solution_metadata = json.dumps({
                "challenge": inputs["challenge"],
                "solution": None,
                "signals": [{"name": "Zoey", "value": {"Present": fp}}],
                "checksum": checksum,
                "existing_token": None,
                "client": "Browser",
                "domain": self.domain,
                "metrics": self._generate_metrics(),
                "goku_props": self.goku_props,
            }, separators=(',', ':'))
            return {
                "solution_data": solution_data,
                "solution_metadata": solution_metadata
            }

        # Standard JSON payload for other challenge types
        return {
            "challenge": inputs["challenge"],
            "checksum": checksum,
            "solution": verify(inputs["challenge"]["input"], checksum, inputs["difficulty"]),
            "signals": [{"name": "Zoey", "value": {"Present": fp}}],
            "existing_token": None,
            "client": "Browser",
            "domain": self.domain,
            "metrics": self._generate_metrics(),
        }

    def _generate_metrics(self):
        """Generate random metrics to simulate browser behavior"""
        return [
            {"name": "2", "value": round(random.uniform(0.2, 0.5), 1), "unit": "2"},
            {"name": "100", "value": 0, "unit": "2"},
            {"name": "101", "value": 0, "unit": "2"},
            {"name": "102", "value": random.randint(0, 1), "unit": "2"},
            {"name": "103", "value": random.randint(4, 20), "unit": "2"},
            {"name": "104", "value": 0, "unit": "2"},
            {"name": "105", "value": 0, "unit": "2"},
            {"name": "106", "value": 0, "unit": "2"},
            {"name": "107", "value": 0, "unit": "2"},
            {"name": "108", "value": 0, "unit": "2"},
            {"name": "undefined", "value": 0, "unit": "2"},
            {"name": "110", "value": 0, "unit": "2"},
            {"name": "111", "value": random.randint(5, 30), "unit": "2"},
            {"name": "112", "value": 0, "unit": "2"},
            {"name": "undefined", "value": 0, "unit": "2"},
            {"name": "3", "value": round(random.uniform(4, 10), 1), "unit": "2"},
            {"name": "7", "value": 0, "unit": "4"},
            {"name": "1", "value": round(random.uniform(15, 60), 1), "unit": "2"},
            {"name": "4", "value": round(random.uniform(0.8, 1.6), 1), "unit": "2"},
            {"name": "5", "value": 0, "unit": "2"},
            {"name": "6", "value": round(random.uniform(15, 60), 1), "unit": "2"},
            {"name": "0", "value": round(random.uniform(800, 900), 1), "unit": "2"},
            {"name": "8", "value": 1, "unit": "4"}
        ]

    def verify(self, payload, challenge_type=None):
        self.session.headers = {
            "connection": "keep-alive",
            "sec-ch-ua-platform": "\"Windows\"",
            "user-agent": self.user_agent,
            "sec-ch-ua": "\"Chromium\";v=\"136\", \"Google Chrome\";v=\"136\", \"Not.A/Brand\";v=\"99\"",
            "content-type": "text/plain;charset=UTF-8",
            "sec-ch-ua-mobile": "?0",
            "accept": "*/*",
            #"origin": "https://www.binance.com",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            #"referer": "https://www.binance.com/",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "en-US,en;q=0.9"
        }

        # Check if this is mp_verify (has solution_data key)
        if "solution_data" in payload:
            return self._verify_mp_verify(payload)

        # Standard JSON request for other challenge types
        res = self.session.post(
            f"https://{self.endpoint}/verify",
            json=payload).json()
        return res["token"]

    def _verify_mp_verify(self, payload):
        """Send multipart/form-data request for mp_verify"""
        from curl_cffi.curl import CurlMime

        multipart = CurlMime()
        multipart.addpart(name="solution_data", data=payload['solution_data'])
        multipart.addpart(name="solution_metadata", data=payload['solution_metadata'])

        self.session.headers.update({
            "origin": f"https://{self.domain}",
            "referer": f"https://{self.domain}/",
            "content-type": "multipart/form-data",
            "accept": "*/*",
            "accept-language": "zh-CN,zh;q=0.9",
            "priority": "u=1, i",
        })

        res = self.session.post(
            f"https://{self.endpoint}/mp_verify",
            multipart=multipart,
        )
        multipart.close()

        result = res.json()
        return result.get("token")

    def __call__(self):
        inputs = self.get_inputs()
        payload = self.build_payload(inputs)
        return self.verify(payload)
