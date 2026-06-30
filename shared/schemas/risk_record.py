"""
Shared risk record schema for CloudSentinel.

All scanner modules import build_risk_record() to ensure consistent
DynamoDB record shapes. Each module fills in module-specific fields
on top of the base schema defined here.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List


VALID_PRIORITIES     = {"Critical", "High", "Medium", "Low"}
VALID_STATUSES       = {"OPEN", "IN_PROGRESS", "RESOLVED"}
VALID_CLOUD_PROVIDERS = {"AWS", "GCP", "Azure"}


@dataclass
class RiskRecord:
    resourceId:           str
    riskTimestamp:        str
    module:               str
    cloudProvider:        str
    resource:             str
    resourceName:         str
    riskType:             str
    riskReason:           str
    riskPriority:         str
    remediationSteps:     List[str] = field(default_factory=list)
    alternativeSolutions: List[str] = field(default_factory=list)
    aiExplanation:        str = ""
    riskCategory:         str = ""
    status:               str = "OPEN"
    region:               str = ""
    source:               str = "scanner"   # "scanner" | "aws-config"

    def __post_init__(self):
        if self.riskPriority not in VALID_PRIORITIES:
            raise ValueError(f"riskPriority must be one of {VALID_PRIORITIES}")
        if self.status not in VALID_STATUSES:
            raise ValueError(f"status must be one of {VALID_STATUSES}")
        if self.cloudProvider not in VALID_CLOUD_PROVIDERS:
            raise ValueError(f"cloudProvider must be one of {VALID_CLOUD_PROVIDERS}")

    def to_dict(self):
        return asdict(self)


def make_resource_id(module: str, resource: str, resource_name: str) -> str:
    """Generate a deterministic, DynamoDB-safe partition key."""
    safe_res  = resource.lower().replace(" ", "-")
    safe_name = resource_name.lower().replace(" ", "-").replace("/", "-")[:60]
    return f"{module}-{safe_res}-{safe_name}"


def build_risk_record(
    module:               str,
    resource:             str,
    resource_name:        str,
    risk_type:            str,
    risk_reason:          str,
    priority:             str,
    remediation_steps:    List[str] = None,
    alternative_solutions: List[str] = None,
    cloud_provider:       str = "AWS",
    region:               str = "",
) -> dict:
    """
    Returns a plain dict ready for DynamoDB PutItem.
    Use this in all scanner modules so every record has the same shape.
    """
    return RiskRecord(
        resourceId           = make_resource_id(module, resource, resource_name),
        riskTimestamp        = datetime.now(timezone.utc).isoformat(),
        module               = module,
        cloudProvider        = cloud_provider,
        resource             = resource,
        resourceName         = resource_name,
        riskType             = risk_type,
        riskReason           = risk_reason,
        riskPriority         = priority,
        remediationSteps     = remediation_steps or [],
        alternativeSolutions = alternative_solutions or [],
        region               = region,
    ).to_dict()
