import requests
from config import GITHUB_HEADERS, GITHUB_ORG, RISK_PRIORITY, escalate_risk


def get_github_members():

    members = []

    url = f'https://api.github.com/orgs/{GITHUB_ORG}/members?per_page=100'

    while True:
        response = requests.get(url, headers=GITHUB_HEADERS)

        try:
            response.raise_for_status()

        except requests.exceptions.HTTPError as e:
            print(f"HTTP error occured: {e}")
            return members

        except requests.exceptions.RequestException as e:
            print(f'Request Failed: {e}')
            return members

        batch = response.json()
        members.extend(batch)

        if 'next' in response.links:
            url = response.links['next']['url']

        else:
            break

    mfa_response = requests.get( 
        f'https://api.github.com/orgs/{GITHUB_ORG}/members?filter=2fa_disabled&per_page=100', 
        headers=GITHUB_HEADERS
        )
    
    try:
        mfa_response.raise_for_status()
        mfa_disabled_logins = [member['login'] for member in mfa_response.json()]

    except requests.exceptions.HTTPError as e:
        print(f"Could not fetch MFA status: {e}")
        mfa_disabled_logins = []

    for member in members:
        member['mfa_disabled'] = member['login'] in mfa_disabled_logins

    
    return members

def get_outside_collaborators():
    collaborators = []

    url = f'https://api.github.com/orgs/{GITHUB_ORG}/outside_collaborators?per_page=100'

    while True:
        response = requests.get(url, headers=GITHUB_HEADERS)

        try:
            response.raise_for_status()

        except requests.exceptions.HTTPError as e:
            print(f"HTTP error occured: {e}")
            return collaborators

        except requests.exceptions.RequestException as e:
            print(f'Request Failed: {e}')
            return collaborators
        
        batch = response.json()
        collaborators.extend(batch)

        if 'next' in response.links:
            url = response.links['next']['url']

        else:
            break

    return collaborators


def get_github_repos():
    repos = []

    url = f'https://api.github.com/orgs/{GITHUB_ORG}/repos?per_page=100'

    while True:
        response = requests.get(url, headers=GITHUB_HEADERS)

        try:
            response.raise_for_status()

        except requests.exceptions.HTTPError as e:
            print(f"HTTP error occured: {e}")
            return repos

        except requests.exceptions.RequestException as e:
            print(f'Request Failed: {e}')
            return repos
        
        batch = response.json()
        repos.extend(batch)

        if 'next' in response.links:
            url = response.links['next']['url']

        else:
            break

    return repos

    

def analyse_github_risks(members, collaborators, repos):
    git_findings = []

    for member in members:

        username = member.get('login', 'Unknown')
        role = member.get('role', 'Unknown')
        mfa_disabled = member.get('mfa_disabled', False)
        account_type = member.get('type', 'Unknown')

        risks = []
        risk_level = 'Informational'

        if account_type != 'Bot': # Skips Bot accounts for checking MFA since they cannot have it enabled

            if mfa_disabled and role == 'owner': # Checks if account is Owner and if mfa is disabled - Critical
                risks.append({
                    'type': 'OWNER Account MFA Disabled',
                    'description': f'{username} has no MFA enabled on a Owner account',
                    'recommendation': 'Enable MFA'
                })
                risk_level = escalate_risk(risk_level, 'Critical')

            if mfa_disabled and role == 'member': # Checks if account is user and if mfa is disabled - High
                risks.append({
                    'type': 'USER Account MFA Disabled',
                    'description': f'{username} has no MFA enabled on a User account',
                    'recommendation': 'Enable MFA'
                })
                risk_level = escalate_risk(risk_level, 'High')

        if role == 'owner': # Checks accounts for owners - Could break least privilege guidelines
            risks.append({
                'type': 'Owner Account',
                'description': f'{username} is an owner',
                'recommendation': 'Check if they should be owner - They could have unneccessary permissions'
            })
            risk_level = escalate_risk(risk_level, 'Informational')

        if account_type == 'Bot': # Checks type for a bot account
            risks.append({
                'type': 'Bot Account',
                'description': f'{username} is an Bot',
                'recommendation': 'Review the accounts permissions to check if they follow least privilege'
            })
            risk_level = escalate_risk(risk_level, 'Informational')

        git_findings.append({
            'username': username,
            'role': role,
            'mfa_disabled': mfa_disabled,
            'account_type': account_type,
            'risks': risks,
            'risk_level': risk_level
            })
        

    for collaborator in collaborators:
        risks = []
        risk_level = 'Informational'
        collaborator_username = collaborator.get('login', 'Unknown')
        collaborator_type = collaborator.get('type', 'Unknown')

        risks.append({

            'type': 'Collaborator Account',
            'description': f'{collaborator_username} is a external collaborator',
            'recommendation': 'Review collaborator account and remove if unnecessary'

            })
        risk_level = escalate_risk(risk_level, 'Medium')
        
        git_findings.append({
            'username': collaborator_username,
            'role': 'Outside Collaborator',
            'mfa_disabled': 'N/A',
            'account_type': collaborator_type,
            'risks': risks,
            'risk_level': risk_level

        })


    for repo in repos:
        risks = []
        risk_level = 'Informational'
        repo_name = repo.get('name', 'Unknown')
        is_private = repo.get('private', True)


        if not is_private:
            risks.append({
                'type': 'Public Repository',
                'description': f'{repo_name} is a public repository',
                'recommendation': 'Review if this repo should be public - consider making it private'
            })

            risk_level = escalate_risk(risk_level, 'Medium')
        git_findings.append({

            'username': repo_name,
            'role': 'Repository',
            'mfa_disabled': 'N/A',
            'account_type': 'Repo',
            'risks': risks,
            'risk_level': risk_level
        })

      
        
    return git_findings




#### MOCK DATA####



def get_mock_github_members():
    return [
        {   # Owner, No MFA - Should be Critical
            'login': 'admin',
            'role': 'owner',       # 'owner' or 'member'
            'type': 'User',       # 'User' or 'Bot'
            'mfa_disabled': True  # True or False
        },
        {   # Member, No MFA - Should be High
            'login': 'member2',
            'role': 'member',      
            'type': 'User',      
            'mfa_disabled': True  
        },
        {   # Owner, MFA enabled - Should be Informational
            'login': 'IT_Manager',
            'role': 'owner',      
            'type': 'User',      
            'mfa_disabled': False  
        },
        {   # Bot, MFA cannot be enabled
            'login': 'BOTAccount',
            'role': 'member',      
            'type': 'Bot',      
            'mfa_disabled': False 
        },
        {   # Healthy Member, MFA enabled - Should be Informational
            'login': 'jane_doe',
            'role': 'member',      
            'type': 'User',      
            'mfa_disabled': False 

        }
    ]


def get_mock_collaborators():
    return [
        { # Should return medium - Extneral collaborators need justification
            'login': 'Colaborator1',
            'type': 'User'
        }
    ]

def get_mock_repos():
    return [ 
       {   # Public repo — Medium risk
            'name': 'public-website',
            'private': False,
            'permissions': {
                'admin': False,
                'push': True,
                'pull': True
            }
        },
        {   # Private repo — Informational
            'name': 'internal-tooling',
            'private': True,
            'permissions': {
                'admin': False, # Admin checks 
                'push': True,
                'pull': True
            }
        }
    ]
