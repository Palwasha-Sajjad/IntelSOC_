"""Basic health endpoint. Does not yet test database or queue connections."""
from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
def health_check() -> dict[str, str]:
    """Confirm that the FastAPI application is running."""
    return {"status": "ok", "service": "intelsoc-backend"}
