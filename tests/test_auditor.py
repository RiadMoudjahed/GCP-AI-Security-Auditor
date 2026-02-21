from unittest import mock
from unittest.mock import patch, MagicMock
import google.auth.exceptions
from auditor.core.auditor import GCPAISecurityAuditor

def test_auth_failure():
    with patch("google.auth.default", side_effect=google.auth.exceptions.DefaultCredentialsError("no creds")):
        auditor = GCPAISecurityAuditor("test-project")
        assert auditor.credentials is None
        assert any(f["Check"] == "auth" for f in auditor.findings)
def test_check_storage_security_public_bucket():
    mock_bucket = MagicMock()
    mock_bucket.name = "risky-bucket"
    mock_bucket.public_access_prevention = "inherited"
    mock_bucket.default_kms_key_name = None

    with patch("google.cloud.storage.Client") as mock_client:
        mock_client.return_value.list_buckets.return_value = [mock_bucket]
        auditor = GCPAISecurityAuditor("test-project")
        auditor.check_storage_security()
        assert any(f["Check"] == "storage-security" for f in auditor.findings)

def test_check_iam_security_public_binding():
    mock_policy = MagicMock()
    mock_policy.bindings = [
        MagicMock(role="roles/owner", members=["allUsers"]),
    ]

    with patch("google.cloud.resourcemanager_v3.ProjectsClient") as mock_client:
        mock_client.return_value.get_iam_policy.return_value = mock_policy
        auditor = GCPAISecurityAuditor("test-project")
        auditor.check_iam_security()
        assert any (f["Check"] == "iam-security" for f in auditor.findings)
      
def test_generate_report(capsys):
    auditor = GCPAISecurityAuditor("test-project")
    auditor.findings = [
        {"Severity": "CRITICAL", "Check": "iam-security", "message": "test finding"}
    ]
    auditor.generate_report()
    captured = capsys.readouterr()
    assert "CRITICAL" in captured.out

def test_check_vertex_ai_security():
    mock_instance = MagicMock()
    mock_instance.name = "risky-notebook"
    mock_instance.no_public_ip = False
    mock_instance.no_proxy_access = False
    
    with patch("google.cloud.notebooks_v1.NotebookServiceClient") as mock_client:
        mock_client.return_value.list_instances.return_value = [mock_instance]
        auditor = GCPAISecurityAuditor("test-project")
        auditor.check_vertex_ai_security()
        assert any(f["Check"] == "ai-security" for f in auditor.findings)

def test_run_all_checks():
    auditor = GCPAISecurityAuditor("test-project")
    auditor.check_vertex_ai_security = MagicMock()
    auditor.check_storage_security = MagicMock() 
    auditor.check_iam_security = MagicMock()
    auditor.generate_report = MagicMock()
    auditor.run_all_checks = MagicMock()
