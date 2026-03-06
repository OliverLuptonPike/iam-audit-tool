from datetime import datetime, timedelta, timezone
from config import escalate_risk


def get_workspace_users(service):
    user_list = [] # Declared inside the function but NOT in the loop to save after each iteration
    page_token = None # Becuase the google API sends page by page not all at once

    while True:
        results = service.users().list(customer='my_customer', maxResults=100, pageToken=page_token).execute()
        batch = results.get('users', [])
        user_list.extend(batch)

        page_token = results.get('nextPageToken')  # Pagination logic - If next page token is there then continue
        if not page_token: # If not Break the while loop
            break

    return user_list




def analyse_user_risks(users):
    findings = []
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=90)

    for user in users:
        email = user.get('primaryEmail', 'Unknown') # Gets user email
        mfa_enabled = user.get('isEnrolledIn2Sv', False) # Checks if MFA is enabled on the account
        is_admin = user.get('isAdmin', False) # Gets admin status 
        last_login_time = user.get('lastLoginTime', None) # gets login time
        suspended = user.get('suspended', False) # Checks if the account is suspended

        risks = []
        risk_level = 'Informational'
        last_login = None


        # LAST LOGIN
        if last_login_time and last_login_time != '1970-01-01T00:00:00.000Z':
            try:
                last_login = datetime.fromisoformat(last_login_time.replace('Z', '+00:00'))

                if last_login < cutoff_date and is_admin: # Checks if the admin account has logged in within 90 days
                    risks.append({
                        'type': 'Inactive Account ADMIN ACCOUNT',
                        'description': f'{email} has not logged in within 90 days and IS ADMIN',
                        'recommendation': 'Suspend the admin account and investigate ASAP'
                    })
                    risk_level = escalate_risk(risk_level, 'Critical')

                if last_login < cutoff_date and not is_admin: # Checks if the User account has logged in wihtin 90 days
                    risks.append({
                        'type': 'Inactive Account',
                        'description': f'{email} has not logged in within 90 days',
                        'recommendation': 'Suspend the account and investigate'
                    })
                    risk_level = escalate_risk(risk_level, 'High')
                    

            except ValueError:
                print ("TimeStamp could not be converted for", email)
               

        else: 

            if is_admin:
                risks.append({
                            'type': 'ADMIN ACCOUNT Never Logged In',
                            'description': f'{email} is ADMIN and has never logged in',
                            'recommendation': 'Disable or delete unused account ASAP'
                })
                risk_level = escalate_risk(risk_level, 'Critical')


            if not is_admin: # Account has never logged in as the return from google = 1970-01-01T00:00:00.000Z which is the Unix timestamp used for never logged in
                risks.append({
                            'type': 'Never Logged In',
                            'description': f'{email} has never logged in',
                            'recommendation': 'Disable or delete unused account'
                })
                risk_level = escalate_risk(risk_level, 'High')

            
        # MFA
        if not mfa_enabled and is_admin: # Checks if mfa is not enabled and is admin
            risks.append({
                'type': 'Admin Account with No MFA enabled',
                'description': f'{email} has not enabled MFA',
                'recommendation': 'Enable MFA'
            })
            risk_level = escalate_risk(risk_level, 'Critical')

        if not mfa_enabled and not is_admin: # Checks if mfa is not enabled and is user
            risks.append({
                'type': 'User account with No MFA enabled',
                'description': f'{email} has not enabled MFA',
                'recommendation': 'Enable MFA'
            })
            risk_level = escalate_risk(risk_level, 'High')


        # Suspended Accounts
        if suspended and is_admin: # Admin account is suspended
            risks.append({
                'type': 'Admin Account is suspended',
                'description': f'{email} ADMIN account is suspended',
                'recommendation': 'Investigate account suspention'
            })
            risk_level = escalate_risk(risk_level, 'Informational')


        if suspended and not is_admin: # User account suspended
            risks.append({
                'type': 'User Account is suspended',
                'description': f'{email} USER account is suspended',
                'recommendation': 'Investigate account suspention'
            })
            risk_level = escalate_risk(risk_level, 'Informational')


        findings.append({ # appends the findings for the user to the findings list
            'email': email,
            'is_admin': is_admin,
            'mfa_enabled': mfa_enabled,
            'last_login': last_login,
            'suspended': suspended,
            'risks': risks,
            'risk_level': risk_level
        })
        

    return findings # Function will return the findings list


      

def get_mock_users():
    return [
        {   # Admin, no MFA, inactive — should be Critical
            'primaryEmail': 'admin@midshire.co.uk',
            'isAdmin': True,
            'isEnrolledIn2Sv': False,
            'lastLoginTime': '2024-06-01T09:00:00.000Z',
            'suspended': False
        },
        {   # User, MFA enabled, inactive — should be High
            'primaryEmail': 'jane.doe@midshire.co.uk',
            'isAdmin': False,
            'isEnrolledIn2Sv': True,
            'lastLoginTime': '2024-06-01T09:00:00.000Z',
            'suspended': False
        },
        {   # Admin, never logged in — should be Critical
            'primaryEmail': 'ghost.admin@midshire.co.uk',
            'isAdmin': True,
            'isEnrolledIn2Sv': False,
            'lastLoginTime': '1970-01-01T00:00:00.000Z',
            'suspended': False
        },
        {   # User, never logged in — should be High
            'primaryEmail': 'ghost.user@midshire.co.uk',
            'isAdmin': False,
            'isEnrolledIn2Sv': False,
            'lastLoginTime': '1970-01-01T00:00:00.000Z',
            'suspended': False
        },
        {   # User, no MFA, active — should be High
            'primaryEmail': 'no.mfa@midshire.co.uk',
            'isAdmin': False,
            'isEnrolledIn2Sv': False,
            'lastLoginTime': '2026-02-01T09:00:00.000Z',
            'suspended': False
        },
        {   # Suspended admin — should be Informational
            'primaryEmail': 'suspended.admin@midshire.co.uk',
            'isAdmin': True,
            'isEnrolledIn2Sv': True,
            'lastLoginTime': '2026-01-01T09:00:00.000Z',
            'suspended': True
        },
        {   # Healthy user — MFA on, active, not admin — should be Informational
            'primaryEmail': 'healthy.user@midshire.co.uk',
            'isAdmin': False,
            'isEnrolledIn2Sv': True,
            'lastLoginTime': '2026-02-01T09:00:00.000Z',
            'suspended': False
        }
    ]

