from dotenv import load_dotenv
import os
from azure.data.tables import TableServiceClient
from azure.core.credentials import AzureNamedKeyCredential
from msal import ConfidentialClientApplication
import datetime
import pytz
import json
from azure.core.exceptions import ResourceNotFoundError
import uuid
import AzureKVHelper as AzureKvHelper




# Load environment variables from .env file
load_dotenv()

# Access the environment variable
_envname = os.getenv('ENV_NAME')
print(f'MySettingName: {_envname}')
tenant_id = os.getenv('AZURE_TENANT_ID')
client_id = os.getenv('AZURE_CLIENT_ID')
client_secret = os.getenv('AZURE_CLIENT_SECRET')


storage_account_name = os.getenv('STORAGE_ACCNAME')
storage_account_url = f"https://{storage_account_name}.table.core.windows.net"
table_name = os.getenv('TABLE_NAME')

#Reading from KV
key = AzureKvHelper.get_secret('TABLE-KEY')
#key = os.getenv('TABLE_KEY')


credential = AzureNamedKeyCredential(storage_account_name, key)
# Create a ClientSecretCredential object [Service Principal]
# credential = ClientSecretCredential(tenant_id, client_id, client_secret)   


service = TableServiceClient(
            endpoint = storage_account_url,
            credential = credential
            )
table_client = service.get_table_client(table_name = table_name)



def Get_Token(request_time):

    try:
        result = Generate_Token()
        if 'access_token' in result:
                result_json = json.dumps(result)
                entity = {
                    'PartitionKey': 'partition1',
                    'RowKey': str(uuid.uuid4()),
                    'Token': result_json,
                    'Exp_Time' : result['expires_in'],
                    'Creation_Time' : request_time,
                    'status' : 1
                    }
        table_client.create_entity(entity=entity)
        print(f"row inserted into table {table_name}")
        return result 
        
        '''
        entities = table_client.list_entities()
        entitylist= list(entities)

        if entitylist:
            entity = Check_Time_Range(entitylist,request_time,table_client)

            if entity != None:
                elapsed_time = request_time - entity['Creation_Time']
                remaining_time = datetime.timedelta(seconds=entity['Exp_Time']) - elapsed_time
                entity['Exp_Time'] = remaining_time.total_seconds()
                entity['Creation_Time'] = request_time
                result_dict = json.loads(entity['Token'])
                result_dict['expires_in'] = remaining_time.total_seconds()
                result_dict['ext_expires_in'] = remaining_time.total_seconds()
                table_client.update_entity(entity)
                print("Entity updated successfully.")
                return result_dict
            
            else:
                print("All Tokens Expired. Creating new one....")
                result = Generate_Token()
                if 'access_token' in result:
                    result_json = json.dumps(result)
                    entity = {
                        'PartitionKey': 'partition1',
                        'RowKey': str(uuid.uuid4()),
                        'Token': result_json,
                        'Exp_Time' : result['expires_in'],
                        'Creation_Time' : request_time,
                        'status' : 1
                        }
                table_client.create_entity(entity=entity)
                print(f"row inserted into table {table_name}")
                return result
                
        else:
            print("Entity not found, creating a new one.")
            result = Generate_Token()
            if 'access_token' in result:
                result_json = json.dumps(result)
                entity = {
                    'PartitionKey': 'partition1',
                    'RowKey': str(uuid.uuid4()),
                    'Token': result_json,
                    'Exp_Time' : result['expires_in'],
                    'Creation_Time' : request_time,
                    'status' : 1
                    }
            table_client.create_entity(entity=entity)
            print(f"row inserted into table {table_name}")
            return result 
            '''
    except ResourceNotFoundError:
        return "Entity not found!"

def Generate_Token():
    AUTHORITY = f"https://login.microsoftonline.com/{tenant_id}"  
    app = ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=AUTHORITY
    )
    s = ["https://management.azure.com/.default"]
    result = app.acquire_token_for_client(scopes=s)
    return result


def Check_Time_Range(entities, request_time,table_client):
    for entity in entities:
        creation_time = entity['Creation_Time']
        status = entity['status']
        if status == 1:
            exp_in = entity['Exp_Time']
            if creation_time.tzinfo is None:
                creation_time = creation_time.replace(tzinfo=pytz.UTC)
            if request_time.tzinfo is None:
                request_time = request_time.replace(tzinfo=pytz.UTC)
            expiration_time = creation_time + datetime.timedelta(seconds=exp_in)
            if creation_time <= request_time <= expiration_time:
                return entity
            else:
                entity['status'] = 0
        table_client.update_entity(entity)    
    return None   
    
           

def Degenerate(token):
    entities = table_client.list_entities()
    for entity in entities:
        result_dict = json.loads(entity['Token'])
        if entity['status'] == 1 :
            if token == result_dict['access_token']:
                entity['status'] = 0
                table_client.update_entity(entity)
                return True
        
    return False

def IsValidTokenFromTable(token):    
    
    entities = table_client.list_entities()
    for entity in entities:
        result_dict = json.loads(entity['Token'])
        if entity['status'] == 1 and token == result_dict['access_token'] :            
                return True
        
    return False
    
