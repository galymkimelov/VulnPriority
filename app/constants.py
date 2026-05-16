from enum import Enum


class VulnerabilityStatus(str, Enum):
    OPEN = "Open"
    IN_PROGRESS = "In Progress"
    PENDING_VERIFICATION = "Pending Verification"
    RESOLVED = "Resolved"
    VERIFIED = "Verified"


VALID_STATUSES = [status.value for status in VulnerabilityStatus]
DEFAULT_VULNERABILITY_STATUS = VulnerabilityStatus.OPEN.value
DEFAULT_ASSET_CRITICALITY = 1.0
