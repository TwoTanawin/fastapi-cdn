from fastapi import FastAPI, Response
import base64
import time
import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

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

# ✅ Build a signed CloudFront policy
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

# ✅ Sign the policy using cryptography
def sign_policy(policy: str, private_key_path: str) -> str:
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None  # Set this if your key is encrypted
        )

    signature = private_key.sign(
        data=policy.encode(),
        padding=padding.PKCS1v15(),
        algorithm=hashes.SHA1(),
    )

    return base64.b64encode(signature).decode("utf-8")

# ✅ Set the signed cookies
@app.post("/generate-cdn-cookie")
def get_signed_cookie(response: Response):
    expires = int(time.time()) + 60 * 60  # 1 hour from now
    policy = generate_signed_policy(expires)
    signature = sign_policy(policy, PRIVATE_KEY_PATH)

    response.set_cookie("CloudFront-Policy", base64.b64encode(policy.encode()).decode())
    response.set_cookie("CloudFront-Signature", signature)
    response.set_cookie("CloudFront-Key-Pair-Id", CLOUDFRONT_KEY_PAIR_ID)

    return {"message": "Signed cookies set"}
