import os
import sys
from auditor.core.auditor import GCPAISecurityAuditor

project_id = os.environ.get("GCP_PROJECT_ID")
if project_id is None:
    print("GCP_PROJECT_ID environment variable is not set.")
    sys.exit(1)

auditor = GCPAISecurityAuditor(project_id)
auditor.run_all_checks()
