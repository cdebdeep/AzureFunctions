import os
import json
import logging
import azure.functions as func
import jwt
import requests
from jwt.algorithms import RSAAlgorithm
from azure.identity import ClientSecretCredential



   
tenant_id = os.getenv('AZURE_TENANT_ID')
client_id = os.getenv('AZURE_CLIENT_ID')
client_secret = os.getenv('AZURE_CLIENT_SECRET')
AUTHORITY = f"https://login.microsoftonline.com/{tenant_id}"
ISSUER = f"https://sts.windows.net/{tenant_id}/"
JWKS_URL = f"{AUTHORITY}/discovery/v2.0/keys"
    
def get_jwks():
        response = requests.get(JWKS_URL)
        response.raise_for_status()
        return response.json()
    
def validate_token(token, jwks):
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks['keys']:
            if key['kid'] == unverified_header['kid']:
                rsa_key = {
                    'kty': key['kty'],
                    'kid': key['kid'],
                    'use': key['use'],
                    'n': key['n'],
                    'e': key['e']
                }
        if not rsa_key:
            raise ValueError("Public key not found")

        payload = jwt.decode(
            token,
            key=RSAAlgorithm.from_jwk(json.dumps(rsa_key)),
            algorithms=['RS256'],
            audience="https://management.azure.com",
            issuer=ISSUER
        )
        return payload
    
def get_ClientSecretCredential():
    credential = ClientSecretCredential(tenant_id, client_id, client_secret)
    return  credential   



    
    
 
    