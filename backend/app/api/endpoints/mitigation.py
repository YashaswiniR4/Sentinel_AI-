
"""
SOAR Automated Mitigation & Audit Endpoints
/api/mitigation

All endpoints require an authenticated, active SOC administrator.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status

from backend.app.api.deps import get_current_admin
from backend.app.models.user import User
from backend.app.schemas.mitigation import (
    SOARPolicyOut,
    PolicyToggleRequest,
    SOARAuditLogOut,
)
from backend.app.services.cloud_service import cloud_service


router = APIRouter(
    prefix="/mitigation",
    tags=["SOAR Automated Mitigation"],
)


@router.get(
    "/policies",
    response_model=List[SOARPolicyOut],
)
def get_soar_policies(
    admin: User = Depends(get_current_admin),
):
    """Return configured SOAR policies for administrators."""

    policies = cloud_service.get_soar_policies()

    return [
        SOARPolicyOut(**policy)
        for policy in policies
    ]


@router.patch("/policies/{policy_name}")
def toggle_soar_policy(
    policy_name: str,
    request: PolicyToggleRequest,
    http_request: Request,
    admin: User = Depends(get_current_admin),
):
    """Update a policy and record the authenticated administrator."""

    # Use the authenticated user's identity, not a caller-supplied name.
    admin_username = (
        getattr(admin, "username", None)
        or getattr(admin, "email", None)
        or str(getattr(admin, "id", "unknown"))
    )

    # This is the direct client address seen by the application.
    # Behind a proxy, it may be the proxy address.
    source_ip = (
        http_request.client.host
        if http_request.client is not None
        else "unknown"
    )

    success = cloud_service.toggle_soar_policy(
        policy_name=policy_name,
        enabled=request.enabled,
        admin_username=admin_username,
        source_ip=source_ip,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SOAR Policy '{policy_name}' not found",
        )

    return {
        "message": f"Policy '{policy_name}' updated successfully",
        "enabled": request.enabled,
    }


@router.get(
    "/audit-trail",
    response_model=List[SOARAuditLogOut],
)
def get_soar_audit_trail(
    admin: User = Depends(get_current_admin),
):
    """Return the SOAR audit trail to administrators."""

    logs = cloud_service.get_audit_trail()

    return [
        SOARAuditLogOut(**log)
        for log in logs
    ]
