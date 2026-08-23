#!/usr/bin/env python3
"""Seeds one realistic investigation (+ step, finding, outcome, organizational
memory) into whatever DATABASE_URL points at — used by scripts/smoke-test.sh's
`--full` tier to prove the real chain (casky_db.store write -> casky-ui read)
end-to-end, the same way a completed `casky harness` run would populate it.

Prints the seeded investigation's id on the last line of stdout (and nothing
else there) so the calling script can capture it directly.

Usage:
    DATABASE_URL=postgresql://casky:casky@localhost:55432/casky \
        python3 scripts/seed_smoke_investigation.py
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone

from casky_db import store


def main() -> None:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("DATABASE_URL is not set", file=sys.stderr)
        sys.exit(1)

    investigation_id = str(uuid.uuid4())

    class _Plan:
        id = investigation_id
        domain = "cloud"
        evidence_text = "CloudTrail: StopInstances by user Nikki from 192.0.2.0"
        status = "complete"
        confidence = 0.82
        evidence_gaps = ["missing VPC flow logs"]
        agent_used = "claude"
        model_used = "claude-opus-4-6"
        created_at = datetime.now(timezone.utc).isoformat()
        steps = [
            {
                "id": str(uuid.uuid4()),
                "skill_slug": "aws-cloudtrail-triage",
                "skill_category": "cloud",
                "technique_id": "T1078.004",
                "technique_name": "Valid Accounts: Cloud Accounts",
                "rationale": "Investigate unusual EC2 stop action",
                "evidence_focus": "CloudTrail events",
                "step_order": 0,
                "status": "done",
            },
        ]
        cve_references = []

    store.create_investigation(_Plan(), database_url=database_url)

    store.record_findings(
        investigation_id,
        None,
        [
            {
                "title": "Unusual EC2 StopInstances",
                "severity": "high",
                "description": "Instance stopped outside business hours by a user with no MFA.",
                "proof": "eventName=StopInstances sourceIPAddress=192.0.2.0",
                "mitre_technique": "T1078.004",
                "affected_asset": "i-0123456789abcdef0",
            },
        ],
        database_url=database_url,
    )

    store.record_outcome(
        investigation_id,
        "Confirmed unauthorized EC2 stop; credentials were shared, not compromised.",
        ["T1078.004"],
        database_url=database_url,
    )

    store.store_memory(
        source_investigation_id=investigation_id,
        statement=(
            "StopInstances from this account outside business hours warrants "
            "escalation unless a change ticket exists."
        ),
        rationale="Confirmed in this investigation: no change ticket, shared credentials, no MFA.",
        conditions={"business_hours": False},
        applies_to={"technique_ids": ["T1078.004"]},
        confidence=0.75,
        escalation_recommended=True,
        database_url=database_url,
    )

    print(investigation_id)


if __name__ == "__main__":
    main()
