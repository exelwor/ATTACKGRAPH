"""Fix suggestions. A finding's own ``remediation`` text always wins."""

from __future__ import annotations

from attackgraph.models import Finding, FindingKind

_BY_TAG = (
    ("default_credentials", "Replace default credentials with unique secrets stored in a vault."),
    ("weak_password", "Enforce a password policy and rotate the affected secrets."),
    ("shared_password", "Give every environment and service its own credentials; rotate the shared one."),
    ("plaintext_secrets", "Move secrets out of files and repositories into a secrets manager, then rotate them."),
    ("no_mfa", "Require multi-factor authentication for every interactive and remote login."),
    ("no_edr", "Deploy an endpoint detection agent and alert on its silence."),
    ("no_logging", "Enable audit logging and forward it to a central, write-protected store."),
    ("no_waf", "Put a web application firewall (or equivalent filtering) in front of the service."),
    ("unpatched", "Apply the vendor patch or upgrade to a supported release."),
    ("open_port", "Close the port or restrict it with a firewall rule to the hosts that need it."),
    ("public_access", "Remove public access and require authentication."),
    ("no_auth", "Require authentication and authorization on this interface."),
    ("excessive_permissions", "Apply least privilege: remove rights the account does not need."),
    ("no_encryption", "Enable encryption at rest and in transit."),
    ("no_segmentation", "Segment the network so this host is reachable only from systems that need it."),
)
_BY_KIND = {
    FindingKind.VULNERABILITY: "Patch or upgrade the affected component, or apply the vendor workaround.",
    FindingKind.MISCONFIGURATION: "Correct the configuration to the vendor's hardened baseline.",
    FindingKind.PERMISSION: "Reduce the permissions to the minimum the workload needs.",
    FindingKind.MISSING_CONTROL: "Deploy the missing control and verify it works.",
}


def suggest_action(finding: Finding) -> str:
    if finding.remediation:
        return finding.remediation
    for tag, text in _BY_TAG:
        if tag in finding.tags:
            return text
    return _BY_KIND[finding.kind]
