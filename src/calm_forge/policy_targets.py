"""Provider-keyed policy resource targets — ADR §5 ratification.

Sentinel and tfpolicy are two syntaxes over one intent. When a stack's
``cloud-provider`` is AWS they must both target AWS resources, or
``--policy-framework all`` on an AWS stack would enforce on one emitter and
silently no-op on the other (a Sentinel rule filtering ``azurerm_*`` matches
nothing in an AWS plan). This module is the single source of truth for *which
AWS resources* each predicate checks, so the two emitters cannot drift.

Azure / Kubernetes targets stay inline in each writer — they are the shipped,
golden-locked default and are not re-routed through here. Only the AWS branch is
centralised, because it is the newly-ratified map and the thing most at risk of
diverging between the two syntaxes.

**Deliberately absent — emitted as ``TODO(aws-sme)`` markers, not guessed.** Two
AWS targets have provider-version-sensitive attribute paths where a wrong path
yields a policy that passes review but matches nothing in the plan:
  - S3 server-side encryption — moved to
    ``aws_s3_bucket_server_side_encryption_configuration`` in AWS provider v4.
  - security-group ingress from ``0.0.0.0/0`` — needs iteration over the
    ``ingress`` rule list, not a single attribute compare.
These wait for AWS-SME ratification (see docs/tfpolicy-sprint-report.md).
"""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_CLOUD_PROVIDER = "azure"


def cloud_provider_of(decorators) -> str:
    """The target cloud from a decorators list, defaulting to azure (the shipped path)."""
    decorator = decorators[0] if decorators else {}
    return (decorator.get("data", {}) or {}).get("cloud-provider", DEFAULT_CLOUD_PROVIDER)


@dataclass(frozen=True)
class AwsTarget:
    """One AWS resource a predicate checks, in both emitters' terms.

    ``tfpolicy_condition`` is the *positive* rule (what must hold); ``sentinel_violation``
    is the *negative* filter (what marks a violation). They are stated separately rather
    than derived, so neither syntax mistranslates the other — this table is ratified, not
    computed.
    """

    resource_type: str
    tfpolicy_condition: str
    sentinel_violation: str


# ratified — stable AWS attribute paths (see confidence table in the sprint report)
AWS_ENCRYPTION_AT_REST: list[AwsTarget] = [
    AwsTarget("aws_ebs_volume", "attrs.encrypted == true",
              "rc.change.after.encrypted is not true"),
    AwsTarget("aws_db_instance", "attrs.storage_encrypted == true",
              "rc.change.after.storage_encrypted is not true"),
]

AWS_NO_PUBLIC_ENDPOINTS: list[AwsTarget] = [
    AwsTarget("aws_db_instance", "attrs.publicly_accessible == false",
              "rc.change.after.publicly_accessible is true"),
    AwsTarget("aws_lb", "attrs.internal == true",
              "rc.change.after.internal is not true"),
]

# unratified — flagged in-band so the gap is visible, never a silent wrong path
AWS_ENCRYPTION_TODO = (
    "TODO(aws-sme): ratify S3 server-side encryption "
    "(aws_s3_bucket_server_side_encryption_configuration — provider v4+)"
)
AWS_PUBLIC_ENDPOINT_TODO = (
    "TODO(aws-sme): ratify security-group ingress from 0.0.0.0/0 "
    "(aws_security_group — iterate ingress rules)"
)
