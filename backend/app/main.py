"""IntelSOC backend application entry point."""
from fastapi import FastAPI
from app.api.routes.health import router as health_router
from app.api.routes import services
from app.api.routes import events
from app.api.routes import enrollment
from app.api.routes import device_management

app = FastAPI(
    title="IntelSOC API",
    description="Backend API for the IntelSOC FYP",
    version="0.1.0",
)

app.include_router(health_router, prefix="/api/v1")
app.include_router(services.router, prefix="/api/v1")
app.include_router(events.router, prefix="/api/v1")
app.include_router(enrollment.router, prefix="/api/v1")
app.include_router(device_management.router, prefix="/api/v1")
