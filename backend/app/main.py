"""IntelSOC backend application entry point."""
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.responses import JSONResponse
from app.api.routes.health import router as health_router
from app.api.routes import services
from app.api.routes import events
from app.api.routes import enrollment
from app.api.routes import device_management
from app.api.routes import ai_analysis
from app.api.routes import monitoring
from app.api.routes import auth
from app.api.routes import user_management

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
app.include_router(ai_analysis.router, prefix="/api/v1")
app.include_router(monitoring.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")
app.include_router(user_management.router, prefix="/api/v1")

@app.exception_handler(RequestValidationError)
async def secure_validation_error_handler(
    request: Request,
    exc: RequestValidationError,
):
    path = request.url.path.rstrip("/")

    if (
        path == "/api/v1/auth"
        or path.startswith("/api/v1/auth/")
    ):
        return JSONResponse(
            status_code=422,
            content={
                "detail": "Invalid authentication request"
            },
            headers={
                "Cache-Control": "no-store"
            },
        )

    return await request_validation_exception_handler(
        request,
        exc,
    )
