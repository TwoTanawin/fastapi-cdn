from fastapi import FastAPI, Response
import rsa
import base64
import time
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

CLOUDFRONT_KEY_PAIR_ID = os.getenv("CLOUDFRONT_KEY_PAIR_ID")
PRIVATE_KEY_PATH = os.getenv("CLOUDFRONT_PRIVATE_KEY_PATH")
CLOUDFRONT_DOMAIN = os.getenv("CLOUDFRONT_DOMAIN") 

if not CLOUDFRONT_KEY_PAIR_ID:
    raise EnvironmentError("CLOUDFRONT_KEY_PAIR_ID is missing")
if not PRIVATE_KEY_PATH:
    raise EnvironmentError("CLOUDFRONT_PRIVATE_KEY_PATH is missing")
if not CLOUDFRONT_DOMAIN:
    raise EnvironmentError("CLOUDFRONT_DOMAIN is missing")

def generate_signed_policy(expires_at: int) -> str:
    policy = f"""{{
      "Statement": [
        {{
          "Resource": "{CLOUDFRONT_DOMAIN}*",
          "Condition": {{
            "DateLessThan": {{"AWS:EpochTime": {expires_at} }}
          }}
        }}
      ]
    }}"""
    return policy

def sign_policy(policy: str, private_key_path: str) -> str:
    with open(private_key_path, 'rb') as f:
        priv_key = rsa.PrivateKey.load_pkcs1(f.read())
    signature = rsa.sign(policy.encode('utf-8'), priv_key, 'SHA-1')
    return base64.b64encode(signature).decode('utf-8')

@app.post("/generate-cdn-cookie")
def get_signed_cookie(response: Response):
    expires = int(time.time()) + 60 * 60  # 1 hour
    policy = generate_signed_policy(expires)
    signature = sign_policy(policy, PRIVATE_KEY_PATH)

    response.set_cookie("CloudFront-Policy", base64.b64encode(policy.encode()).decode())
    response.set_cookie("CloudFront-Signature", signature)
    response.set_cookie("CloudFront-Key-Pair-Id", CLOUDFRONT_KEY_PAIR_ID)
    return {"message": "Signed cookies set"}
