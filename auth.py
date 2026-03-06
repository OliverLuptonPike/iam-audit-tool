from config import SCOPES, CREDENTIALS_FILE, TOKEN_FILE
import os
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow


def authenticate_google():
    creds = None
    
    # Block 1 — Load if possible
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    # Block 2 — Obtain if needed
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            # silent refresh 
            request = Request()
            creds.refresh(request)
           
        else:
            # browser flow
            # then flow.run_local_server()
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0) # Finds any port avaiable to send the request

    # Block 3 — Save and return
    with open(TOKEN_FILE, "w") as f:
        f.write(creds.to_json())
        os.chmod(TOKEN_FILE, 0o600) # Means no one other then the owner can read or write to the token.json file
    
    return creds