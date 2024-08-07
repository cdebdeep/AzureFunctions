from azure.identity import UsernamePasswordCredential , InteractiveBrowserCredential,ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient
from dotenv import load_dotenv
import os

import AzureAuthHelper as AzureAuthHelper

load_dotenv()

AZURE_KV_NAME=os.getenv('AZURE_KV_NAME')
KEY_VAULT_URL=os.getenv('KEY_VAULT_URL')


# Authenticate using Service Principal
credential = AzureAuthHelper.get_ClientSecretCredential()


# Initialize the SecretClient
secret_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)
key_client = KeyClient(vault_url=KEY_VAULT_URL, credential=credential)

# Function to get a secret
def get_secret(secret_name):
    try:
        secret = secret_client.get_secret(secret_name)
        return secret.value
    except Exception as e:
        print(f"Failed to get secret '{secret_name}': {e}")
        
# Function to get a Key
def get_key(key_name):
    try:
        key = key_client.get_key(key_name)
        return key.value
    except Exception as e:
        print(f"Failed to get secret '{key_name}': {e}")        


