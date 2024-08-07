import datetime
import azure.functions as func
import logging
import jwt
import json
import os
from dotenv import load_dotenv
import WorkHelper as helper
import pytz
import AzureAuthHelper as AuthHelper


app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="Token_Generator")
def Token_Generator(req: func.HttpRequest) -> func.HttpResponse:
    
    logging.info('Python HTTP trigger function processed a request.')     
    trigger_time = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)

    # Load environment variables from .env file
    load_dotenv()
    _envname = os.getenv('ENV_NAME')
    print(f'MySettingName: {_envname}')
    logging.info('Application Env is: ' + _envname)
        
    result = helper.Get_Token(trigger_time)
    if 'access_token' in result:
        
        response = func.HttpResponse(
            json.dumps(result),
            status_code=200,
            mimetype="application/json"
        )
        response = AddResponseHeaders(response)
        return response
    

    else:
        response = func.HttpResponse(
            json.dumps({"error": "Invalid token"}),
            status_code=401
        )
        response = AddResponseHeaders(response)
        return response
       
@app.route(route="HealthCheck",auth_level=func.AuthLevel.ANONYMOUS)
def HealthCheck(req: func.HttpRequest) -> func.HttpResponse:
     return func.HttpResponse(
                    "Health is Fine.",
                    status_code=200
                )           

@app.route(route="Token_Validity")
def Token_Validity(req: func.HttpRequest)-> func.HttpResponse:
        IsValid=0
        token = req.headers.get("Authorization")
        if not token:
            IsValid=0
        try:
            # Strip 'Bearer ' prefix if present
            if token.startswith("Bearer "):
                token = token[len("Bearer "):]

            # Decode the token without verification to inspect its claims
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            logging.info(f"Unverified token payload: {unverified_payload}")

            # Get JWKS and validate the token
            jwks = AuthHelper.get_jwks()
            payload = AuthHelper.validate_token(token, jwks)            
            IsValid=helper.IsValidTokenFromTable(token)
            
            return func.HttpResponse(
                json.dumps({"IsValid": IsValid, "payload": payload}),
                status_code=200 if IsValid else 401,
                mimetype="application/json"
            )            
            
        except jwt.ExpiredSignatureError:
            return func.HttpResponse("Token has expired", status_code=401)
            LogHelper.fnc_Logger("Token has expired")
        except jwt.InvalidAudienceError:
            return func.HttpResponse("Invalid audience", status_code=401)
            LogHelper.fnc_Logger("Invalid audience")
        except Exception as e:
            logging.error(f"Token validation error: {str(e)}")            
            return func.HttpResponse("Invalid token", status_code=401)
    
   
    
        

@app.route(route="Token_Degenerator", auth_level=func.AuthLevel.FUNCTION)
def Token_Degenerator(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')  

    # Load environment variables from .env file
    load_dotenv()
    _envname = os.getenv('ENV_NAME')
    print(f'MySettingName: {_envname}')
    logging.info('Application Env is: ' + _envname)

    VALIDATE_AUTH=os.getenv('VALIDATE_AUTH')
             
    if VALIDATE_AUTH == "True":

        token = req.headers.get("Authorization")
        if not token:
            response =  func.HttpResponse("Authorization token is missing", status_code=401)
            response = AddResponseHeaders(response)
            return response
        try:
            # Strip 'Bearer ' prefix if present
            if token.startswith("Bearer "):
                token = token[len("Bearer "):]
            result = helper.Degenerate(token)
            if result:
                response = func.HttpResponse("Token degenerated...", status_code=200)
                response = AddResponseHeaders(response)
                return response
            else:
                response = func.HttpResponse("Token Invalid...", status_code=401)
                response = AddResponseHeaders(response)
                return response
            
        except Exception as e:
            logging.error(f"Token validation error: {str(e)}")
            response = func.HttpResponse("Invalid token", status_code=401)    
            response = AddResponseHeaders(response)
            return response   

    else:
        response = func.HttpResponse("No  Authorization...", status_code=401)
        response = AddResponseHeaders(response)
        return response

    
def AddResponseHeaders(response: func.HttpRequest)-> func.HttpResponse:
    response.headers['Content-Security-Policy'] = (
                    "default-src 'self'; "
                    "script-src 'self' https://digisf-dev.azurewebsites.net https://digisf-nonprod-web.azurewebsites.net  https://digistorefront-prod-web.azurewebsites.net; "
                    "style-src 'self' https://styles.example.com"
                )
    response.headers['X-XSS-Protection'] = "1; mode=block"
    response.headers['X-Content-Type-Options'] = "nosniff"
    response.headers['Strict-Transport-Security'] = "max-age=31536000; includeSubDomains; preload"
    response.headers['X-Frame-Options'] = "DENY"
    response.headers['Referrer-Policy'] = "strict-origin-when-cross-origin"
    response.headers['Permissions-Policy'] = "camera=(), fullscreen=(), geolocation=(), gyroscope=(), microphone=(), magnetometer=(), usb=(), midi=(), notifications=(), push=(), sync-xhr=(), speaker=(), vibrate=(), payment=()"
    
    return response


    
   