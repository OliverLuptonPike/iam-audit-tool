from config import RISK_PRIORITY
from collections import Counter

# Create HTML Report
def generate_report(google_findings, github_findings):

    # Summary calculations
    all_findings = google_findings + github_findings
    total = len(all_findings)
    risk_counts = Counter(finding['risk_level'] for finding in all_findings)
    immediate = risk_counts['Critical'] + risk_counts['High']
    monitor = risk_counts['Medium'] + risk_counts['Low']
    informational = risk_counts['Informational']

##risk level | count for each level - How I want the table to look
    summary_html = f'''
    <h2> Executive Summary</h2>
    <p> Total identities audited: {total}</p>

    <table> 
        <thead>
            <tr>
                <th>Risk level</th>
                <th>Count</th>
            </tr>
        </thead>
        <tbody>
            <tr class="Critical"><td>Critical</td><td>{risk_counts['Critical']}</td></tr>
            <tr class="High"><td>High</td><td>{risk_counts['High']}</td></tr>
            <tr class="Medium"><td>Medium</td><td>{risk_counts['Medium']}</td></tr>
            <tr class="Low"><td>Low</td><td>{risk_counts['Low']}</td></tr>
            <tr class="Informational"><td>Informational</td><td>{risk_counts['Informational']}</td></tr>
        </tbody>
    </table>

    <p> Immediate attention required: {immediate} risks </p>
    <p> Findings that should be monitored: {monitor} risks </p>
    <p> Number of informational risks: {informational} </p>
    '''


    sorted_google_risks = sorted(google_findings, key=lambda x: RISK_PRIORITY[x['risk_level']], reverse=True) # lambda is anonymous function. It allows for simple one-line functions
    sorted_github_risks = sorted(github_findings, key=lambda x: RISK_PRIORITY[x['risk_level']], reverse=True)

#| Email | Role | Risk Level | Risk Types | - How I want the table to look
    google_rows = ''
    github_rows = ''
    
    for finding in sorted_google_risks:
        risk_types = ', '.join([risk['type'] for risk in finding['risks']]) or 'No issues found'
        google_rows += f'<tr class="{finding["risk_level"]}"><td>{finding.get("email") or finding.get("username", "Unknown")}</td><td>{finding.get("role") or ("Admin" if finding.get("is_admin") else "User")}</td><td>{finding["risk_level"]}</td><td>{risk_types}</td></tr>'
       
    for finding in sorted_github_risks:
        risk_types = ', '.join([risk['type'] for risk in finding['risks']]) or 'No issues found'
        github_rows += f'<tr class="{finding["risk_level"]}"><td>{finding.get("email") or finding.get("username", "Unknown")}</td><td>{finding.get("role") or ("Admin" if finding.get("is_admin") else "User")}</td><td>{finding["risk_level"]}</td><td>{risk_types}</td></tr>'

    html = f'''
    <html>
        <head>
            <style>
            .Critical  {{ background-color: #ff4444; color: white; }}
            .High      {{ background-color: #ff8800; color: white; }}
            .Medium    {{ background-color: #ffcc00; }}
            .Low       {{ background-color: #88cc00; }}
            .Informational {{ background-color: #aaaaaa; }}
            body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }}
            h2 {{ color: #333; }}
            p {{ color: #333; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 30px; background-color: white; box-shadow: 0 1px 3px rgba(0,0,0,0.2); }}
            th {{ background-color: #333; color: white; padding: 12px; text-align: left; }}
            td {{ padding: 10px 12px; border-bottom: 1px solid #ddd; }}
            tr:hover {{ opacity: 0.9; }}

            </style>
        </head>
            <body>
                {summary_html}

                <h2> Google WorkSpace Audit</h2>
                <table>
                    <thead>
                        <tr>
                        <th>Identity</th>
                        <th>Role</th>
                        <th>Risk Level</th>
                        <th>Risk Types</th>
                        </tr>
                    </thead>
                    <tbody>
                    
                    {google_rows}

                    </tbody>
                </table>

                <h2> GitHub Audit</h2>
                <table>
                    <thead>
                        <tr>
                        <th>Identity</th>
                        <th>Role</th>
                        <th>Risk Level</th>
                        <th>Risk Types</th>
                        </tr>
                    </thead>
                    <tbody>
                    {github_rows}
                    </tbody>
                </table>
                
            </body>
    </html>
    '''

    with open('report.html', 'w') as f:
        f.write(html)    
