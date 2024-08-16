import os
import json
import requests
from collections import defaultdict
from datetime import datetime, timedelta, time
import calendar


class report:
    def __init__(self):
        with open("config.json", "r") as config:
            config = json.loads(config.read())
        self.report_day = config['report_day']
        self.report_day_id = list(calendar.day_name).index(self.report_day.capitalize())
        # Tenant ID
        self.tenant_ids = {}
        for tenant in config['tenant_ids']:
            self.tenant_ids[tenant['alias']] = tenant['tenant_id']
        # TP Settings
        self.exclude_mail_tps = config['exclude_mail_tps']
        self.exclude_benign_positive_alarms = config['exclude_benign_positive_alarms']
        self.exclude_tps_by_keywords = {}
        self.exclude_tps_by_keywords = config['exclude_tps_by_keywords']
        # Cookie
        self.cookies = {}
        for tenant in config['tenant_ids']:
            self.cookies[tenant['alias']] = tenant['cookie']

        self.tenant_id, self.cookie = self.select_tenant()
        clear_screen()
        cookie_keys_to_extract = ['sccauth', 'XSRF-TOKEN', 'ai_session', 's.SessID', 'SSR']
        cookie_values = self.extract_values_from_cookie(self.cookie, cookie_keys_to_extract)
        self.sccauth = cookie_values['sccauth']
        self.xsrf_token = cookie_values['XSRF-TOKEN'].replace('%3A', ":")
        self.ai_session = cookie_values['ai_session']
        self.sess_id = cookie_values['s.SessID']
        self.ssr = cookie_values['SSR']
        # Report date range
        self.from_date, self.to_date = self.get_report_date_range()
        self.edit_list = []
        self.activated = 0
        self.passed = 0
        self.i = 0
        self.start_time = datetime.now()

    def select_tenant(self):
        # List the available aliases
        print("\nAvailable Tenants:\n")
        for i, alias in enumerate(self.tenant_ids.keys(), start=1):
            print(f"{i}. {alias}")

        # Select a tenant ID by alias
        while True:
            alias_input = input("\nEnter the number of the desired alias: ")
            try:
                alias_num = int(alias_input)
                if 1 <= alias_num <= len(self.tenant_ids):
                    selected_alias = list(self.tenant_ids.keys())[alias_num - 1]
                    selected_cookie = list(self.cookies.keys())[alias_num - 1]
                    return self.tenant_ids[selected_alias], self.cookies[selected_cookie]
                else:
                    print("Invalid input. Please try again.")
                    exit()
            except ValueError:
                print("Invalid input. Please try again.")
                exit()

    def get_report_start_time(self, relative_time):
            # Determine what day of the week it is
            today_weekday = relative_time.weekday()  # Monday 0, Tuesday 1, ..., Friday 4, ..., Sunday 6

            # Calculate the last report day before today
            days_since_last_report_day = (today_weekday - self.report_day_id) % 7
            if days_since_last_report_day == 0:
                days_since_last_report_day = 7  # If today is report day, take the previous report day

            last_report_day_date = relative_time - timedelta(days=days_since_last_report_day)
            
            # Set the start time of the day after the report day (Ex: Saturday 00:00:00)
            next_day = last_report_day_date + timedelta(days=1)
            next_day_start = datetime.combine(next_day, time.min)

            # add 1 minute
            next_day_start = next_day_start + timedelta(minutes=1)

            report_start_time = next_day_start.strftime("%Y-%m-%dT%H:%M:%S.000Z")

            return report_start_time

    def get_report_end_time(self, relative_time):
        # Determine what day of the week it is
        today_weekday = relative_time.weekday()  # Monday 0, Tuesday 1, ..., Friday 4, ..., Sunday 6

        # If today is report day
        if today_weekday == self.report_day_id:
            next_report_day_date = relative_time
        else:
            # Calculate first report day after today
            days_until_next_report_day = (self.report_day_id - today_weekday + 7) % 7  # Cuma 4. gün
            next_report_day_date = relative_time + timedelta(days=days_until_next_report_day)

        # Set last time of day (23:59:59)
        next_report_day_end = datetime.combine(next_report_day_date, time.max)
        next_report_day_end_formatted = next_report_day_end.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        return next_report_day_end_formatted

    def get_report_date_range(self):
        # Get today's date
        today = datetime.today()
        # Ask user if they are within the report date range
        response = input("Are you within the report date range? (y/n) ")
        if response.lower() == 'y':
            from_data = self.get_report_start_time(today)
            to_date = self.get_report_end_time(today)

            return from_data, to_date
        else:
            # Determine what day of the week it is
            today_weekday = today.weekday()
            difference = today_weekday + self.report_day_id + 1
            # Calculate X day ago (difference)
            relative_back_shifted_time = today - timedelta(days=difference)
            from_data = self.get_report_start_time(relative_back_shifted_time)
            to_date = self.get_report_end_time(relative_back_shifted_time)

            return from_data, to_date

    def get_incidents(self):
        incidents = []
        page_index = 0
        uri = "https://security.microsoft.com/apiproxy/mtp/incidentQueue/incidents/alerts"
        headers, cookies = self.generate_header_data()
        print("[+] Incidents Downloading...")
        # This method is working like 'Export' download button. Max page size is 50
        while True:
            page_index += 1
            print("page_index: ", page_index)
            post_data = self.generate_post_data(page_index)
            response = requests.post(uri, json = post_data, headers = headers, cookies = cookies)
            if response.text == '[]':
                break
            if response.status_code != 200:
                print("Response: ", response.text)
                raise Exception("Unable to get incidents from tenant, did the session time out?")
            incidents.extend(json.loads(response.text))

        return incidents

    def get_devices(self):
        devices = []
        page_index = 0
        headers, cookies = self.generate_header_data()
        print("[+] Devices Downloading...")
        # This method is working like 'Export' download button. Max tested page size is 200
        while True:
            page_index += 1
            uri = f"https://security.microsoft.com/apiproxy/mtp/k8s/machines?tid={self.tenant_id}&deviceCategories=Endpoint&onBoardingStatuses=Onboarded&lookingBackIndays=7&pageIndex={page_index}&pageSize=200"
            print("page_index: ", page_index)
            response = requests.get(uri, headers = headers, cookies = cookies)
            if response.text == '[]':
                break
            devices.extend(json.loads(response.text))
            if response.status_code != 200:
                print("Response: ", response.text)
                raise Exception("Unable to get devices from tenant, did the session time out?")

        return devices

    def group_severities_by_classification(self, incidents, target_classification):
        # Create a default dictionary to hold groups
        severity_groups = defaultdict(list)

        # Group incidents by severity for the target classification
        for incident in incidents:
            if incident.get("Classification") == target_classification:
                severity = incident.get("Severity", "Unspecified")
                severity_groups[severity].append(incident)

        return severity_groups

    def group_incident_categories(self, incidents): 
        # Create a default dictionary to hold groups
        category_groups = defaultdict(list)

        # Group category
        for incident in incidents:
            if self.exclude_benign_positive_alarms:
                if incident.get("Classification") == classifications["Benign Positive"]:
                    continue
            category = incident.get("Categories", "Unspecified")[0]
            category_groups[category].append(incident)

        return category_groups

    def group_device_oses(self, devices): 
        # Create a default dictionary to hold groups
        os_groups = defaultdict(list)

        # Group devices os
        for device in devices:
            os = device.get("OsPlatform", "Unspecified")
            if os == "None":
                continue
            os_groups[os].append(device)

        return os_groups

    def group_incident_sources(self, incidents): 
        # Create a default dictionary to hold groups
        incident_source_groups = defaultdict(list)
        incident_source_short_names = {
            "Microsoft Defender for Office 365": "Office 365",
            "Microsoft Defender for Endpoint": "Endpoint",
            "Microsoft Defender for Cloud Apps": "Cloud Apps",
            "Microsoft Defender XDR": "Defender XDR"
        }

        # Group incident sources
        for incident in incidents:
            if self.exclude_benign_positive_alarms:
                if incident.get("Classification") == classifications["Benign Positive"]:
                    continue
            source = incident.get("ProductNames", "Unspecified")[0]
            if source in incident_source_short_names:
                source = incident_source_short_names[source]
            incident_source_groups[source].append(incident)

        return incident_source_groups

    def detect_impacted_entities(self, data):
        # Get the impacted entities dictionary
        impacted_entities = data.get("ImpactedEntities", {})

        # Get ComputerDnsName values from the Machines list
        machines = impacted_entities.get("Machines", [])
        if machines:
            computer_dns_names = [machine.get("ComputerDnsName") for machine in machines if machine.get("ComputerDnsName")]
            if computer_dns_names:
                return ", ".join(computer_dns_names)

        # If Machines list is empty, get UserName values from the Users list
        users = impacted_entities.get("Users", [])
        if users:
            user_names = [user.get("UserName") for user in users if user.get("UserName")]
            if user_names:
                return ", ".join(user_names)

        # If Users list is also empty, get DisplayName values from the Mailboxes list
        mailboxes = impacted_entities.get("Mailboxes", [])
        if mailboxes:
            display_names = [mailbox.get("DisplayName") for mailbox in mailboxes if mailbox.get("DisplayName")]
            if display_names:
                return ", ".join(display_names)

        # If all lists are empty, return an empty string
        return ""
    
    def get_analyst_comment(self, incident_id):
        headers, cookies = self.generate_header_data()
        uri = f"https://security.microsoft.com/apiproxy/mtp/auditHistory/AuditHistory?&entityType=IncidentEntity&id={incident_id}&auditType=0&pageIndex=1&pageSize=100"
        response = requests.get(uri, headers = headers, cookies = cookies)
        if response.status_code != 200:
            print("Response: ", response.text)
            raise Exception("Unable to get the audit history from tenant, did the session time out?")

        data = response.json()
        for item in data:
            if item.get("type") == "Feedback":
                return item.get("newValue")
        return None

    def get_tp_incident_count(self, incidents):
        count = 0
        for incident in incidents:
            if incident.get("Classification") != 20:
                continue  # Skip incidents that are not TP IDs
            count += 1
        return count

    def print_tp_severity_dist(self, incidents):
        grouped_severities = self.group_severities_by_classification(incidents, classifications["True Positive"])
        print(f"\n\x1b[1;31;43m[+] TP Severity Distribution\x1b[0;0m\n")
        for severity, incidents in grouped_severities.items():
            print(f"{severities[severity]}\t{len(incidents)}")

    def print_incidents_category_dist(self, incidents):
        grouped_incident_categories = self.group_incident_categories(incidents)
        print(f"\n\x1b[1;31;43m[+] Incidents Category Distribution\x1b[0;0m\n")
        for category, incidents in grouped_incident_categories.items():
            print(f"{category}\t{len(incidents)}")

    def print_device_os_dist(self, devices):
        total_device_count = len(devices)
        grouped_device_oses = self.group_device_oses(devices)
        print(f"\n\x1b[1;31;43m[+] Device OS Distribution\x1b[0;0m\n")
        for os_name, devices in grouped_device_oses.items():
            print(f"{os_name}\t{len(devices)}")
        print(f"Grand Total\t{total_device_count}")

    def print_tp_incidents_and_comments(self, incidents):
        print(f"\n\x1b[1;31;43m[+] TP Incidents Table\x1b[0;0m\n")
        tp_incident_id_list = []

        for incident in incidents:
            classification = incident.get("Classification")
            if classification != classifications["True Positive"]:
                continue  # Skip incidents that are not TP IDs

            incident_source = incident.get("ProductNames")[0]
            incident_name = incident.get("Title")

            # Exclude conditions
            if self.exclude_mail_tps:
                if incident_source in ["Microsoft Defender XDR", "Microsoft Defender for Office 365"]:
                    continue  # Skip if incident source is excluded
                if self.contains_any(incident_name, *self.exclude_tps_by_keywords):
                    continue  # Skip if incident name contains excluded keywords
            else:
                if self.contains_any(incident_name, *self.exclude_tps_by_keywords):
                    continue  # Skip if incident name contains excluded keywords

            last_activity = incident.get("LastUpdateTime")
            severity = severities.get(incident.get("Severity"), "Unknown")
            impacted_entities = self.detect_impacted_entities(incident)
            incident_id = incident.get("IncidentId")

            # Format last activity time
            last_activity = last_activity.split('.')[0]
            formatted_time = datetime.strptime(last_activity, "%Y-%m-%dT%H:%M:%S").strftime("%d-%m-%Y - %H:%M")

            # Print TP incident details
            print(f"{incident_id}\t{formatted_time}\t{incident_name}\t{severity}\tTrue Positive\t{impacted_entities}")

            tp_incident_id_list.append(incident_id)

        print(f"\n\x1b[1;31;43m[+] TP Incidents Analyst Feedback Comments\x1b[0;0m\n")
        # Print Analyst Feedback Comments
        for incident_id in tp_incident_id_list:
            analyst_comment = self.get_analyst_comment(incident_id)
            print(f"• ({incident_id}) {analyst_comment}")

    def print_incident_source_dist(self, incidents):
        grouped_incident_sources = self.group_incident_sources(incidents)
        print(f"\n\x1b[1;31;43m[+] Incident Sources Distribution\x1b[0;0m\n")
        for source, incidents in grouped_incident_sources.items():
            print(f"{source}\t{len(incidents)}")

    def generate_header_data(self):
        headers = {
            "authority": "security.microsoft.com",
            "method": "POST",
            "path": f"/apiproxy/mtp/huntingService/rules?tenantIds[]={self.tenant_id}",
            "scheme": "https",
            "accept": "application/json, text/plain, */*",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "tr-tr",
            "m-connection": "4g",
            "m-viewid": "",
            "origin": "https://security.microsoft.com",
            "priority": "u=1, i",
            "referer": "https://security.microsoft.com/v2/advanced-hunting?tid={self.tenant_id}",
            "sec-ch-ua": '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "tenant-id": self.tenant_id,
            "x-accepted-statuscode": "3..|4..|50.",
            "x-clientpage": "hunting-2@wicd-hunting",
            "x-tabvisible": "visible",
            "x-tid": self.tenant_id,
            "x-xsrf-token": self.xsrf_token
        }

        cookies = {
            "SSR": self.ssr,
            "at_check": "true",
            "BCP": "AD=1&AL=1&SM=1",
            "SRCHHPGUSR": "SRCHLANG=tr&DM=1&PV=15.0.0&CIBV=1.1418.9-suno",
            "i18next": "tr-TR",
            "s.SessID": self.sess_id,
            "s.Flight": "",
            "sccauth": self.sccauth,
            "X-PortalEndpoint-RouteKey": "neuprod_northeurope",
            "XSRF-TOKEN": self.xsrf_token,
            "ai_session": self.ai_session
        }

        return headers, cookies

    def generate_post_data(self, page_index):
        return {
            "isDexLicense": False,
            "isStatusFilterEnable": False,
            "isUSXIncidentAssignmentEnabled": True,
            "pageSize": 50,
            "isMultipleIncidents": True,
            "serviceSources": {
                "1": [
                    "AutomatedInvestigation",
                    "CustomDetection",
                    "MTP",
                    "CustomerTI",
                    "Bitdefender,Ziften,SentinelOne,Lookout",
                    "WindowsDefenderSmartScreen",
                    "WindowsDefenderAv",
                    "WindowsDefenderAtp"
                ],
                "2": [
                    "8192"
                ],
                "4": [
                    "16384"
                ],
                "8": [
                    "OfficeATP"
                ],
                "16": [
                    "CustomDetection",
                    "MTP",
                    "Manual"
                ],
                "32": [
                    "AAD"
                ],
                "64": [
                    "AppGPolicy",
                    "AppGDetection"
                ]
            },
            "fromDate": self.from_date,
            "toDate": self.to_date,
            "pageIndex": page_index,
            "sortOrder": "Descending",
            "sortByField": "LastUpdateTime"
        }

    def extract_values_from_cookie(self, cookie, keys):
        # Split the cookie string into individual key-value pairs
        cookie_pairs = cookie.split('; ')
        # Convert to dictionary for easy access
        cookie_dict = {pair.split('=')[0]: pair.split('=')[1] for pair in cookie_pairs}
        # Extract the desired values
        extracted_values = {key: cookie_dict.get(key) for key in keys}
        return extracted_values

    def contains_any(self, incident_name, *texts):
        return any(text in incident_name for text in texts)

severities = {
    32: 'Informational',
    64: 'Low',
    128: 'Medium',
    256: 'High',
}

classifications = {
    'False Positive': 10,
    'True Positive': 20,
    'Benign Positive': 30 
}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

if __name__ == '__main__':
    report = report()
    clear_screen()
    incidents = report.get_incidents()
    devices = report.get_devices()

    clear_screen()

    # Report Date Range
    print("\n\x1b[1;31;43m[+] Report date range\x1b[0;0m\n")
    from_date = datetime.strptime(report.from_date, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%d.%m.%y")
    to_date = datetime.strptime(report.to_date, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%d.%m.%y")
    print(from_date, "–", to_date)

    # Total Incident
    tp_incident_count = report.get_tp_incident_count(incidents)
    total_incident = len(incidents)
    print(f"\n\x1b[1;31;43m[+] Total Incident\x1b[0;0m\n")
    print(f"Total: {total_incident} - TP: {tp_incident_count}")

    # TP Severity Distribution
    report.print_tp_severity_dist(incidents)

    # Incidents Category Distribution
    report.print_incidents_category_dist(incidents)

    # Total number of devices
    total_device_count = len(devices)
    print(f"\n\x1b[1;31;43m[+] Total Device\x1b[0;0m\n")
    print(total_device_count)

    # OS Distribution
    report.print_device_os_dist(devices)

    # TP Incidents and Comments
    report.print_tp_incidents_and_comments(incidents)

    # Incident Source Distribution
    report.print_incident_source_dist(incidents)


    end_time = datetime.now()
    print("\n\n\x1b[1;31;43m[!]Elapsed time: ", end_time - report.start_time, "\x1b[0;0m\n")
    print("==================================================")
