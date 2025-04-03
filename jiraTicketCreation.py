import requests
import json
from typing import Dict
from datetime import datetime, timedelta
from config import JIRA_URL, JIRA_API_TOKEN, JIRA_USER_EMAIL, PROJECT_KEY, ISSUE_TYPE  # Import from config.py

# Constants for JIRA ticket creation
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json"
}

PRIORITY_LEVELS = {
    "Highest": 1,
    "High": 2,
    "Medium": 3,
    "Low": 4
}

SLA_DAYS = {
    "Highest": 2,
    "High": 5,
    "Medium": 14,
    "Low": 30
}

# Determine issue priority based on vulnerability risk factors
def calculate_priority(risk_factors: Dict) -> str:
    if risk_factors == "None identified":
        return "Low"
    priority_score = 0
    if risk_factors.get("Public-Facing"):
        priority_score += 3
    if risk_factors.get("Deployed"):
        priority_score += 2
    if risk_factors.get("Loaded Package"):
        priority_score += 1
    if risk_factors.get("OS Condition"):
        priority_score += 1
    if priority_score >= 5:
        return "Highest"
    elif priority_score >= 3:
        return "High"
    elif priority_score >= 1:
        return "Medium"
    else:
        return "Low"

# Calculate due date based on SLA/priority
def calculate_due_date(priority: str) -> str:
    current_date = datetime(2025, 4, 2)
    sla_days = SLA_DAYS.get(priority, 30)
    due_date = current_date + timedelta(days=sla_days)
    return due_date.strftime("%Y-%m-%d")

# Generate JIRA ticket for each impacted project
def create_jira_ticket(project_name: str, project_id: str, risk_factors: Dict, cve_id: str) -> Dict:
    priority = calculate_priority(risk_factors)
    due_date = calculate_due_date(priority)
    summary = f"Vulnerability {cve_id} in {project_name}"
    description = (
        f"Application '{project_name}' (Project ID: {project_id}) is impacted by {cve_id}.\n\n"
        f"**Risk Factors:** {json.dumps(risk_factors, indent=2)}\n\n"
        f"**Due Date:** {due_date} (based on {SLA_DAYS[priority]}-day SLA for {priority} priority)\n\n"
        "Please investigate and remediate this vulnerability."
    )
    payload = {
        "fields": {
            "project": {"key": PROJECT_KEY},
            "summary": summary,
            "description": description,
            "issuetype": {"name": ISSUE_TYPE},
            "priority": {"name": priority},
            "duedate": due_date
        }
    }
    url = f"{JIRA_URL}/rest/api/3/issue"
    auth = (JIRA_USER_EMAIL, JIRA_API_TOKEN)
    response = requests.post(url, headers=HEADERS, auth=auth, data=json.dumps(payload))
    if response.status_code not in (201, 200):
        raise Exception(f"Failed to create JIRA ticket for {project_name}: {response.status_code} - {response.text}")
    return response.json()

# Main function to create JIRA tickets for impacted projects using above functions
def main(impacted_projects: Dict, cve_id: str):
    try:
        if not impacted_projects:
            print("No impacted projects provided. No tickets created.")
            return
        print(f"Creating JIRA tickets for projects impacted by {cve_id}...")
        for project_name, details in impacted_projects.items():
            project_id = details["Project ID"]
            risk_factors = details["Risk Factors"]
            print(f"\nCreating ticket for {project_name}...")
            ticket = create_jira_ticket(project_name, project_id, risk_factors, cve_id)
            ticket_key = ticket.get("key")
            priority = calculate_priority(risk_factors)
            due_date = calculate_due_date(priority)
            print(f"Created ticket: {JIRA_URL}/browse/{ticket_key} (Priority: {priority}, Due: {due_date})")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    # Example integration with Snyk script
    from snyk_scan import main as snyk_main
    impacted_projects = snyk_main()
    if impacted_projects:
        cve_id = input("Confirm CVE ID for JIRA tickets: ")
        main(impacted_projects, cve_id)