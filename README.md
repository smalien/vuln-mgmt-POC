# Vulnerability Management POC

This repository contains Python scripts to identify applications impacted by a specific CVE using the Snyk API and create prioritized JIRA tickets for vulnerability remediation. The process can be run manually or automated using a SIEM integration or AWS services for data ingestion, transformation, and notification.

This can be adapted to leverage vulnerability scan report and risk factor data from other sources but Snyk, as a leader in SCA, has been selected for the POC.

## Repository Contents

- **`snyk_scan.py`**: Queries the Snyk API for projects impacted by a given CVE and extracts risk factors (Deployed, Public-Facing, Loaded Package, OS Condition).
- **`jira_tickets.py`**: Creates JIRA tickets from the Snyk output, setting priority and SLA-based configurable due dates (default: 2, 5, 14, 30 days).
- **`config.example.py`**: Template for configuration (API tokens, URLs, etc.). Copy to `config.py` and fill in your secrets.
- **`owners.json` (optional)**: Maps projects to JIRA account IDs for pre-assignment (example provided).

## Prerequisites

- Python 3.6+ with `requests` (`pip install requests`).
- Snyk API token and Organization ID.
- JIRA API token, instance URL, and project key (e.g., `VULN`).
- Git installed for version control.

## Setup

1. **Clone the Repository**:
- `git clone <repository-url>`
- `cd <repository-name>`


2. **Configure Secrets**:
- Copy `config.example.py` to `config.py`:
  ```
  cp config.example.py config.py
  ```
- Edit `config.py` with your Snyk and JIRA credentials (do not commit `config.py`).

3. **Exclude Secrets**:
- Ensure `.gitignore` includes:
  ```
  config.py
  secrets.json
  ```

4. **(Optional) Define Owners**:
- Define owners' JIRA IDs in `owners.json` to map projects to JIRA ticket assignees:
  ```
  {
    "my-web-app": "557058:abc123-def456",
    "backend-service": "557058:xyz789-ghi012"
  }
  ```

## Manual Usage

1. **Run Snyk Scan**:
`python snyk_scan.py`
- Uses the Snyk output to create tickets with priorities and due dates.
- Confirm the CVE ID when prompted.

## Automation Options

Below are two methods to automate this process: SIEM integration or AWS services.

### Option 1: SIEM Integration

Integrate with a Security Information and Event Management (SIEM) system (e.g., Splunk, Elastic, or Sumo Logic) to trigger the scripts based on CVE alerts and notify asset owners.

#### Workflow

1. **CVE Trigger**:
- Configure the SIEM to monitor CVE feeds (e.g., NVD RSS, vendor alerts) or internal vulnerability scans.
- Create a SIEM alert rule for new CVEs with a severity threshold (e.g., CVSS ≥ 7.0).

2. **Script Execution**:
- Set up a SIEM action to run `snyk_scan.py` with the CVE ID(s) as an argument:
  ```
  python snyk_scan.py <CVE-ID> > snyk_output.json
  ```
- Pipe the output to `jira_tickets.py`:
  ```
  python jira_tickets.py <CVE-ID> < snyk_output.json
  ```
- Use a SIEM script action or webhook to execute this on a server.

3. **Notification**:
- Configure the SIEM to email asset owners using JIRA filter links:
  - Create JIRA filters for each priority (e.g., `project = VULN AND priority = Highest AND "CVE ID" = "<CVE-ID>"`).
  - Use the SIEM’s email action to send a template with links (see [Email Template](#email-template)).
- Assign tickets via `owners.json` or ask owners to self-assign.

#### Example: Splunk

- **Alert**: “New CVE with CVSS ≥ 7.0 detected.”
- **Action**: Run a custom command:
`/path/to/python /path/to/snyk_scan.py cveid | /path/to/python /path/to/jira_tickets.py cveid`

- **Email**: Splunk alert email with JIRA filter URLs.

#### Requirements

- SIEM with scripting/email capabilities.
- Server to run scripts (e.g., an EC2 instance or on-premises host).

### Option 2: AWS Data Ingestion, Transformation, and Notification

Use AWS services to ingest CVE data, process it, and notify owners via email.

#### Architecture

- **Amazon EventBridge**: Triggers on new CVE data.
- **AWS Lambda**: Runs the scripts or calls APIs.
- **Amazon S3**: Stores intermediate outputs.
- **AWS Step Functions**: Orchestrates the workflow.
- **Amazon SNS**: Sends email notifications.

#### Workflow

1. **Data Ingestion**:
 - **Source**: Subscribe to an NVD feed (e.g., JSON via HTTPS) or upload scan results to S3.
 - **EventBridge Rule**: Trigger on S3 upload or schedule daily to fetch NVD updates:
   ```
   {
       "source": ["aws.s3"],
       "detail-type": ["Object Created"],
       "detail": {"bucket": {"name": "cve-input-bucket"}}
   }
   ```

2. **Transformation**:
 - **Lambda (Snyk Scan)**:
   - Trigger: EventBridge.
   - Code: Modify `snyk_scan.py` as a Lambda function to accept a CVE ID from the event, query Snyk, and write output to S3 (`snyk_output.json`).
   - Example:
     ```
     import json
     import boto3
     from snyk_scan import find_projects_by_cve  # Import logic

     s3 = boto3.client("s3")
     def lambda_handler(event, context):
         cve_id = event["cve_id"]
         impacted_projects = find_projects_by_cve(cve_id)
         s3.put_object(
             Bucket="cve-output-bucket",
             Key=f"{cve_id}_output.json",
             Body=json.dumps(impacted_projects)
         )
         return {"cve_id": cve_id, "output_key": f"{cve_id}_output.json"}
     ```
 - **Step Functions**:
   - Step 1: Run Snyk Lambda.
   - Step 2: Pass output to JIRA Lambda.
 - **Lambda (JIRA Tickets)**:
   - Trigger: Step Functions.
   - Code: Modify `jira_tickets.py` to read from S3 and create tickets:
     ```
     import json
     import boto3
     from jira_tickets import create_jira_ticket

     s3 = boto3.client("s3")
     def lambda_handler(event, context):
         cve_id = event["cve_id"]
         output_key = event["output_key"]
         obj = s3.get_object(Bucket="cve-output-bucket", Key=output_key)
         impacted_projects = json.loads(obj["Body"].read())
         for project_name, details in impacted_projects.items():
             create_jira_ticket(project_name, details["Project ID"], details["Risk Factors"], cve_id)
         return {"status": "Tickets created"}
     ```

3. **Notification**:
 - **SNS Topic**: Create a topic (e.g., `VulnNotifications`).
 - **Lambda (Email)**:
   - Trigger: Step Functions success.
   - Code: Fetch JIRA filter URLs (hardcode or query JIRA API) and send via SNS:
     ```
     import boto3
     import json

     sns = boto3.client("sns")
     def lambda_handler(event, context):
         cve_id = event["cve_id"]
         message = f"""Subject: Action Required: Vulnerabilities in Your Systems ({cve_id})
         Hi Team,
         See JIRA tickets for {cve_id}:
         - Highest: {JIRA_URL}/issues/?filter=12345
         - High: {JIRA_URL}/issues/?filter=12346
         - Medium: {JIRA_URL}/issues/?filter=12347
         - Low: {JIRA_URL}/issues/?filter=12348
         Assign yourself if not pre-assigned.
         """
         sns.publish(TopicArn="arn:aws:sns:region:account-id:VulnNotifications", Message=message)
         return {"status": "Email sent"}
     ```
 - Subscribe asset owners’ emails/applicable mailing list(s) to the SNS topic.

#### Requirements

- AWS account with S3, Lambda, Step Functions, SNS, and EventBridge.
- Config stored in AWS Secrets Manager (update scripts to fetch from there instead of `config.py`).

#### Setup

1. Create S3 buckets (`cve-input-bucket`, `cve-output-bucket`).
2. Deploy Lambda functions with script code and `requests` layer.
3. Define Step Functions state machine to chain Lambdas.
4. Set up EventBridge rule and SNS topic.

## Email Template

For both SIEM and AWS:
```
Subject: Action Required: Vulnerabilities in our systems (CVE ID)

Hi Team,

We’ve identified vulnerabilities in our systems for [CVE ID].
This is particularly a risk for public-facing systems as the scope of potential threat actors is much more broad.

Please review and act on the JIRA tickets linked to below, prioritizing your impacted systems by risk level as categorized below:

Highest Priority (2-day SLA)
[JIRA_URL]/issues/?filter=12345  
High Priority (5-day SLA)
[JIRA_URL]/issues/?filter=12346  
Medium Priority (14-day SLA)
[JIRA_URL]/issues/?filter=12347  
Low Priority (30-day SLA)
[JIRA_URL]/issues/?filter=12348 

Next Steps:  
Assign tickets to yourself or the appropriate member of your team in JIRA if not pre-assigned.  

Update tickets with details (e.g., public-facing status) within 48 hours in not pre-identified. 

Contact the Security team [email] with questions.

Thank you for your cooperation,
[Your name/Team name]
```

## Assignment

- **Pre-Assignment**: Use `owners.json` to set assignees in `jira_tickets.py`.
- **Self-Assignment**: If unknown, leave unassigned and request owners to assign via the email.

## Contributing

- Fork, branch, and submit PRs for enhancements.
- Keep `config.py` and secrets out of commits
    - `config.py` should remain in `.gitignore`

## License

MIT License