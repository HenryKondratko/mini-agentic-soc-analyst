from app.retrieval import retrieve_runbook


def test_suspicious_login_retrieves_credential_compromise():
    name, _, score = retrieve_runbook("suspicious login credential compromise failed authentication")
    assert name == "credential_compromise.md"
    assert score > 0


def test_malware_terms_retrieve_malware_response():
    name, _, _ = retrieve_runbook("malware persistence endpoint containment")
    assert name == "malware_response.md"


def test_powershell_terms_retrieve_powershell_runbook():
    name, _, _ = retrieve_runbook("suspicious PowerShell script command line")
    assert name == "suspicious_powershell.md"
