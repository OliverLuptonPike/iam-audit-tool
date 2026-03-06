from googleapiclient.discovery import build
from config import USE_MOCK_DATA
from auth import authenticate_google
from google_audit import get_mock_users, get_workspace_users, analyse_user_risks
from report import generate_report
from github_audit import get_mock_collaborators, get_mock_github_members, get_mock_repos, analyse_github_risks, get_github_members, get_github_repos, get_outside_collaborators

# Main function
def main():
    if USE_MOCK_DATA:
        users = get_mock_users()

    else:
        creds = authenticate_google()
        service = build('admin', 'directory_v1', credentials=creds)
        users = get_workspace_users(service)

        
    google_findings = analyse_user_risks(users) # Analyses google findings

    if USE_MOCK_DATA:
        members = get_mock_github_members()
        collaborators = get_mock_collaborators()
        repos = get_mock_repos()

    else:
        members = get_github_members()
        collaborators = get_outside_collaborators()
        repos = get_github_repos()

    github_findings = analyse_github_risks(members, collaborators, repos) # Analyses github findings


    generate_report(google_findings, github_findings) # Generates the report

    print("[+] Report generated: report.html")


    
if __name__ == '__main__':
    main()