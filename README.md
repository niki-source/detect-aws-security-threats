# detect-aws-security-threats
Automated detection and alerting for suspicious AWS cloud activities using CloudTrail logs and IAM policy monitoring.

#  Cloud Security Alerting & Automation with AWS

**Author:** Niharika Kalkeri  
**Tools:** AWS (EC2, S3, IAM, CloudTrail, Config, SNS), Python, Boto3, GeoIP

---

##  Project Summary

Cloud misconfigurations — especially around IAM permissions and lack of logging — are a leading cause of real-world data breaches. In this project, I built a simulated cloud environment in AWS and developed an automated alerting system using Python and CloudTrail to detect:

- Privilege escalation
- Unauthorized access from foreign countries
- Dangerous API actions (e.g., deleting buckets, attaching policies)

This project reflects real-world scenarios like the 2019 **Capital One breach**, and demonstrates how cloud security can be strengthened with proper architecture, least privilege, and log monitoring.

---

##  Real-World Problem

Organizations often:
- Over-permission IAM roles or users
- Disable or misconfigure logging (CloudTrail, Config)
- Fail to monitor critical API actions

**Result:** Attackers can escalate privileges, access sensitive data, or delete resources without being noticed.

---

##  What This Project Does

This solution simulates an AWS environment and detects suspicious behavior by:
- **Parsing CloudTrail logs** using Python and Boto3
- **Flagging high-risk API calls**, such as:
  - `DeleteBucket`
  - `AttachRolePolicy`
  - Root account logins
- **Geolocating IPs** to detect API calls from suspicious countries
- **Generating alerts** (via console log, CSV, or SNS)


---

##  Key Components

###  IAM Policies
- **EC2 Admin Role**: Access to EC2 only, no access to S3 or IAM
- **Developer Role**: Read-only S3 access, no access to EC2 or policy changes

###  AWS Services Used
- **EC2**: Target of API activity
- **S3**: Contains sensitive files, logs CloudTrail data
- **IAM**: Roles/policies configured with least privilege
- **CloudTrail**: Logs all API activity
- **AWS Config**: Tracks changes to Security Groups and IAM
- **SNS** *(Optional)*: Sends alert notifications

###  Python Script
- Parses CloudTrail logs
- Flags risky API events and root logins
- Uses `geoip2` to map IP addresses to countries
- Outputs alert log as `flagged_events.csv`

---

###  Sample Output

```csv
Time,EventName,Username,SourceIP,GeoLocation,ActionTaken
2025-08-04 10:22,AttachRolePolicy,dev-user,197.64.33.17,Nigeria,ALERT_SENT
2025-08-04 10:24,DeleteBucket,test-admin,104.91.22.2,United States,ALERT_SENT


---

## 🔎 Example Attacker Behavior This Catches

- Privileged IAM misuse (e.g., developer trying to attach `AdministratorAccess`)
- Suspicious geographic access (e.g., API calls from countries outside normal business operations)
- Account compromise (e.g., root login activity)
- Destructive actions (e.g., S3 bucket deletion)

---

## 🧠 Lessons Learned

- The principle of least privilege is the foundation of cloud security  
- Logging is only useful if you monitor it  
- Automation reduces response time and improves consistency  
- Real breaches like Capital One (2019) could have been mitigated with similar alerting and IAM safeguards

---

## 🚀 How to Run This Locally

### 1. Set Up AWS Environment
- Launch an EC2 instance and S3 bucket  
- Enable CloudTrail across all regions  
- Create IAM roles using sample policies in `iam_policies/`

### 2. Install Requirements
```bash
pip install boto3 geoip2

### 3. Run Script
```bash
python cloudtrail_alerts.py

---

## 📂 Repo Structure
cloud-security-aws-alerting/
├── README.md
├── cloudtrail_alerts.py
├── flagged_events.csv
├── iam_policies/
│ ├── ec2_admin_policy.json
│ └── developer_policy.json
├── requirements.txt

---
## 📚 References

- Capital One Breach Analysis (2019)  
- AWS CloudTrail Docs  
- GeoIP2 Python Library  

---

## 🧑‍💻 Author

**Niharika Kalkeri**  
Aspiring Cybersecurity Analyst | Security+ | AWS | Python  
