import google.auth
from google.cloud import notebooks_v1
from google.api_core import exceptions
from google.cloud import storage
from google.cloud import resourcemanager_v3
from collections import defaultdict
import os
import sys


class GCPAISecurityAuditor:


    def __init__(self, project_id: str):
        self.project_id = project_id
        self.findings = []
        try:
            self.credentials, self.detected_project = google.auth.default()
        except google.auth.exceptions.DefaultCredentialsError as e:
            self.credentials = None
            self.findings.append({"Severity": "CRITICAL", "Check": "auth", "message": str(e)})
            print(f"[AUTH ERROR] {e}")


    def check_vertex_ai_security(self):
        try:
            # Create a client
            client = notebooks_v1.NotebookServiceClient(credentials=self.credentials)
    
            # Initialize request arguments
            request = notebooks_v1.ListInstancesRequest(
                parent=f"projects/{self.project_id}/locations/-",
            )
    
            # Make the request
            page_result = client.list_instances(request=request)
    
            # Handle the response
            for response in page_result:
                if response.no_public_ip is False:
                    self.findings.append({"Severity": "CRITICAL", "Check": "ai-security", "message": f"Instance with public IP: {response.name}"})
                if response.no_proxy_access is False:
                    self.findings.append({"Severity": "HIGH", "Check": "ai-security", "message": f"Instance with proxy access: {response.name}"})
        except exceptions.PermissionDenied as e:
            self.findings.append({"Severity": "HIGH", "Check": "ai-security", "message": f"Notebooks API disabled or permission denied: {str(e)}"})

    

    def check_storage_security(self):
        # Initialize the client
        storage_client = storage.Client(project=self.project_id, credentials=self.credentials)

        # List all buckets
        buckets_iterator = storage_client.list_buckets()
        for bucket in buckets_iterator:
            if bucket.public_access_prevention == "inherited":
                self.findings.append({"Severity": "HIGH", "Check": "storage-security", "message": f"Bucket with public access prevention inherited: {bucket.name}"})
            if bucket.default_kms_key_name is None:
                self.findings.append({"Severity": "MEDIUM", "Check": "storage-security", "message": f"Bucket without default KMS key: {bucket.name}"})


    def check_iam_security(self):
        # Initialize the client
        client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)

        # Get the IAM policy
        policy = client.get_iam_policy(resource=f"projects/{self.project_id}")

        for binding in policy.bindings:
            if "allUsers" in binding.members or "allAuthenticatedUsers" in binding.members:
                self.findings.append({"Severity": "CRITICAL", "Check": "iam-security", "message": f"Public IAM binding on role: {binding.role}"})
            if binding.role == "roles/owner" or binding.role == "roles/editor":
                self.findings.append({"Severity": "HIGH", "Check": "iam-security", "message": f"{', '.join(binding.members)} IAM binding on role: {binding.role}"})
            for member in binding.members:
                if member.startswith("serviceAccount:") and binding.role in ["roles/owner", "roles/editor"]:
                    self.findings.append({"Severity": "CRITICAL", "Check": "iam-security", "message": f"Service account with owner/editor role: {member}"})

    def generate_report(self):
        print(f"\n{'='*50}")
        print(f"GCP AI Security Audit Report - Project: {self.project_id}")
        print(f"\n{'='*50}")

        count_high = 0
        count_critical = 0
        count_medium = 0
        
        grouped = defaultdict(list)
        for finding in self.findings:
            grouped[finding["Severity"]].append(finding)
            print(f"{finding['Severity']}: {finding['Check']} - {finding['message']}")


            if finding["Severity"] == "MEDIUM":
                count_medium += 1
            elif finding["Severity"] == "HIGH":
                count_high += 1
            elif finding["Severity"] == "CRITICAL":
                count_critical += 1
        total = count_medium + count_high + count_critical

        print(f"\n{'='*50}")
        print(f"Total findings: {total} {count_medium} MEDIUM\n {count_high} HIGH\n {count_critical} CRITICAL\n")
        print(f"\n{'='*50}")

    def run_all_checks(self):
        self.check_vertex_ai_security()
        self.check_storage_security()
        self.check_iam_security()
        self.generate_report()

if __name__ == "__main__":
    project_id = os.environ.get("GCP_PROJECT_ID")
    if project_id is None:
        print("GCP_PROJECT_ID environment variable is not set.")
        sys.exit(1)
    auditor = GCPAISecurityAuditor(project_id)
    auditor.run_all_checks()
