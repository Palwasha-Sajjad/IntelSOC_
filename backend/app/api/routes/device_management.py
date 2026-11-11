from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.security import verify_admin_key
from app.services.device_service import update_device_criticality


router = APIRouter(
    prefix="/devices",
    tags=["device-management"],
)


class CriticalityUpdateRequest(BaseModel):
    criticality: Literal["low", "medium", "high"]


class DeviceManagementResponse(BaseModel):
    device_id: UUID
    hostname: str
    platform: str
    status: str
    criticality: Literal["low", "medium", "high"]
    created_at: datetime
    last_seen_at: datetime | None


@router.patch(
    "/{device_id}/criticality",
    response_model=DeviceManagementResponse,
    dependencies=[Depends(verify_admin_key)],
)
def set_device_criticality(
    device_id: UUID,
    request: CriticalityUpdateRequest,
):
    device = update_device_criticality(
        device_id=device_id,
        criticality=request.criticality,
    )

    if device is None:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    return device
