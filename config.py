import os
from dotenv import load_dotenv



SCOPES = ['https://www.googleapis.com/auth/admin.directory.user.readonly']
CREDENTIALS_FILE = 'credentials.json'
TOKEN_FILE = 'token.json'
USE_MOCK_DATA = True


load_dotenv()
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
GITHUB_ORG = os.getenv('GITHUB_ORG')
if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN not found in .env file")

if not GITHUB_ORG:
    raise ValueError("GITHUB_ORG not found in .env file")


GITHUB_HEADERS = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

RISK_PRIORITY = {
    'Critical': 4,
    'High': 3,
    'Medium': 2,
    'Low': 1,
    'Informational': 0
}

# Escalastes risk so only the highest level of risk is shown
def escalate_risk(current_level, new_level): 
    
    if RISK_PRIORITY[current_level] < RISK_PRIORITY[new_level]:
        return new_level
    else:
        return current_level
