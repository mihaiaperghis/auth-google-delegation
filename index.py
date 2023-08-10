import os
import base64
import json
import time
import requests
import google.auth
from google.oauth2 import credentials
from google.cloud import iam
import logging

def get_credentials():
    # Step 1: Set up the environment
    service_email = os.environ.get("SERVICE_ACCOUNT_EMAIL")
    user_email = os.environ.get("USER_EMAIL_TO_IMPERSONATE")
    scopes = os.environ.get("GOOGLE_API_SCOPES").split(',')
    
    # Step 2: Get IAM Credentials for the service account that is executing this code
    creds_iam, project = google.auth.default(scopes=["https://www.googleapis.com/auth/iam"])

    # Step 3: Construct the JWT (JSON Web Token)
    payload = {
        "aud": "https://oauth2.googleapis.com/token",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "iss": service_email,
        "scope": " ".join(scopes),
        "sub": user_email,
    }
    header = {"alg": "RS256", "typ": "JWT"}
    jwt_parts = [
        base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"="),
        base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"="),
    ]
    unsigned_jwt = b".".join(jwt_parts).decode()

    # Step 4: Sign the JWT
    client = iam.IAMCredentialsClient(credentials=creds_iam)
    name = f"projects/-/serviceAccounts/{service_email}"
    response = client.sign_blob(request={"name": name, "payload": unsigned_jwt.encode()})
    signed_jwt = f"{unsigned_jwt}.{base64.urlsafe_b64encode(response.signed_blob).rstrip(b'=').decode()}"

    # Step 5: Request an Access Token using the signed JWT
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": signed_jwt,
    }
    response = requests.post(token_url, data=token_data)

    # Step 6: Return the impersonated user Credentials
    if response.status_code == 200:
        token_info = response.json()
        access_token = token_info["access_token"]
        creds = credentials.Credentials(access_token)
        return creds
    
    # Step 7: Error Handling
    else:
        logging.error(f"Failed to obtain access token, response ({response.status_code}): {response.text}")
        raise requests.RequestException(f"Failed to obtain access token, response ({response.status_code}): {response.text}")
