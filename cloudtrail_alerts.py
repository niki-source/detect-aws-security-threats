import boto3
import csv
import geoip2.database
from datetime import datetime, timezone

# Configurations
CLOUDTRAIL_BUCKET = 'cloudtrail-logs-bucket'  # Your CloudTrail S3 bucket name
GEOIP_DB_PATH = 'GeoLite2-Country.mmdb'  # Path to GeoIP2 database file
FLAGGED_EVENTS_CSV = 'flagged_events.csv'

# Suspicious API actions to flag
HIGH_RISK_ACTIONS = [
    'DeleteBucket',
    'AttachRolePolicy',
    'PutBucketPolicy',
    'PassRole',
    'RootLogin'
]

# Countries considered suspicious (example)
SUSPICIOUS_COUNTRIES = ['Nigeria', 'Russia', 'North Korea']

# Initialize AWS clients
cloudtrail_client = boto3.client('cloudtrail')
s3_client = boto3.client('s3')

# GeoIP reader
geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)

def geolocate_ip(ip):
    """Get country name from IP using GeoIP2."""
    try:
        response = geoip_reader.country(ip)
        return response.country.name
    except Exception:
        return "Unknown"

def fetch_cloudtrail_events():
    """
    Fetch recent CloudTrail events.
    You might want to implement pagination or date filters in real usage.
    """
    events = []
    response = cloudtrail_client.lookup_events(
        MaxResults=50  # Adjust as needed
    )
    events.extend(response['Events'])
    return events

def parse_event(event):
    """Parse relevant data from a CloudTrail event."""
    event_name = event['EventName']
    username = event.get('Username', 'Unknown')
    source_ip = event.get('SourceIPAddress', 'Unknown')
    event_time = event['EventTime']
    return event_time, event_name, username, source_ip

def is_suspicious(event_name, username, source_ip):
    """Determine if an event is suspicious."""
    # Check for high-risk actions
    if event_name in HIGH_RISK_ACTIONS:
        return True

    # Example: detect root login
    if event_name == 'ConsoleLogin' and username == 'root' and event.get('ResponseElements', {}).get('ConsoleLogin') == 'Success':
        return True

    # Geo-locate and check suspicious country
    country = geolocate_ip(source_ip)
    if country in SUSPICIOUS_COUNTRIES:
        return True

    return False

def main():
    flagged_events = []

    print("Fetching CloudTrail events...")
    events = fetch_cloudtrail_events()

    for event in events:
        event_time, event_name, username, source_ip = parse_event(event)
        country = geolocate_ip(source_ip)

        flagged = False
        action_taken = "NONE"

        # Flag suspicious events
        if event_name in HIGH_RISK_ACTIONS:
            flagged = True
            action_taken = "ALERT_SENT"
        elif country in SUSPICIOUS_COUNTRIES:
            flagged = True
            action_taken = "ALERT_SENT"

        if flagged:
            flagged_events.append({
                'Time': event_time.strftime("%Y-%m-%d %H:%M"),
                'EventName': event_name,
                'Username': username,
                'SourceIP': source_ip,
                'GeoLocation': country,
                'ActionTaken': action_taken
            })
            print(f"ALERT: {event_name} by {username} from {country} ({source_ip})")

    # Write flagged events to CSV
    with open(FLAGGED_EVENTS_CSV, mode='w', newline='') as csvfile:
        fieldnames = ['Time', 'EventName', 'Username', 'SourceIP', 'GeoLocation', 'ActionTaken']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for event in flagged_events:
            writer.writerow(event)

    print(f"Flagged events written to {FLAGGED_EVENTS_CSV}")

if __name__ == "__main__":
    main()
