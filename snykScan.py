import requests
import json
from typing import Dict, List
from config import SNYK_API_TOKEN, ORG_ID  # Import from config.py

API_BASE_URL = "https://api.snyk.io/rest"
HEADERS = {
    "Authorization": f"token {SNYK_API_TOKEN}",
    "Content-Type": "application/vnd.api+json",
    "Accept": "application/vnd.api+json"
}

# Return all projects from an organization in Snyk
def get_projects() -> List[Dict]:
    """Fetch all projects in the organization."""
    url = f"{API_BASE_URL}/orgs/{ORG_ID}/projects?version=2023-06-22"
    projects = []
    params = {"limit": 100}  # Pagination limit

    while url:
        response = requests.get(url, headers=HEADERS, params=params)
        if response.status_code != 200:
            raise Exception(f"Failed to fetch projects: {response.status_code} - {response.text}")
        
        data = response.json()
        projects.extend(data["data"])
        
        # Handle pagination
        url = data.get("links", {}).get("next")
        if url:
            url = f"{API_BASE_URL}{url}"
        params = {}  # Clear params after first request to use next link directly

    return projects

# Return issues for a given project or projects from Snyk
def get_issues_for_project(project_id: str) -> List[Dict]:
    """Fetch issues for a specific project."""
    url = f"{API_BASE_URL}/orgs/{ORG_ID}/issues?version=2023-06-22"
    params = {
        "project_ids": project_id,
        "limit": 100
    }
    issues = []

    while url:
        response = requests.get(url, headers=HEADERS, params=params)
        if response.status_code != 200:
            raise Exception(f"Failed to fetch issues for project {project_id}: {response.status_code} - {response.text}")
        
        data = response.json()
        issues.extend(data["data"])
        
        # Handle pagination
        url = data.get("links", {}).get("next")
        if url:
            url = f"{API_BASE_URL}{url}"
        params = {}  # Clear params for next link

    return issues

# Return risk factors for a given issue from Snyk
def extract_risk_factors(issue: Dict) -> Dict:
    """Extract applicable risk factors from an issue."""
    risk_factors = {}
    characteristics = issue.get("attributes", {}).get("characteristics", {})

    # Check Snyk AppRisk risk factors
    if characteristics.get("is_deployed"):
        risk_factors["Deployed"] = True
    if characteristics.get("is_public_facing"):
        risk_factors["Public-Facing"] = True
    if characteristics.get("is_loaded_package"):
        risk_factors["Loaded Package"] = True
    if characteristics.get("os_condition_match") is not None:  # Could be True/False
        risk_factors["OS Condition"] = characteristics["os_condition_match"]

    return risk_factors

# Return projects for which issues match a provided CVE ID
def find_projects_by_cve(cve_id: str) -> Dict:
    """Find projects impacted by a CVE and their risk factors."""
    projects = get_projects()
    impacted_projects = {}

    for project in projects:
        project_id = project["id"]
        project_name = project["attributes"]["name"]
        issues = get_issues_for_project(project_id)

        for issue in issues:
            identifiers = issue.get("attributes", {}).get("identifiers", {})
            cve_list = identifiers.get("CVE", [])
            
            if cve_id in cve_list:
                risk_factors = extract_risk_factors(issue)
                impacted_projects[project_name] = {
                    "Project ID": project_id,
                    "Risk Factors": risk_factors if risk_factors else "None identified"
                }
                break  # Stop checking issues once CVE is found

    return impacted_projects

# Main function to identify projects impacted by a specific CVE
def main():
    """Main function to run the script."""
    try:
        print(f"Searching for projects impacted by {CVE_ID}...")
        impacted_projects = find_projects_by_cve(CVE_ID)

        if not impacted_projects:
            print(f"No projects found impacted by {CVE_ID}.")
        else:
            print(f"\nProjects impacted by {CVE_ID}:")
            for project_name, details in impacted_projects.items():
                print(f"\nProject: {project_name}")
                print(f"  Project ID: {details['Project ID']}")
                print(f"  Risk Factors: {details['Risk Factors']}")

    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()