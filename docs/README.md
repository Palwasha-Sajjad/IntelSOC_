# IntelSOC — Module 1A: Backend Foundation

This is the **first working increment**, not a complete SIEM/SOAR product.
It includes a FastAPI backend, a health check, interactive API docs, and two automated tests.

## Requirements
- Windows 10/11, PowerShell, and Python 3.11 or 3.12
- VS Code is recommended

## Run locally (PowerShell)
Open PowerShell in `IntelSOC/backend`.

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Browse to:
- http://127.0.0.1:8000/api/v1/health
- http://127.0.0.1:8000/docs

The health endpoint returns:
```json
{"status":"ok","service":"intelsoc-backend"}
```

## Test (second terminal, also in `IntelSOC/backend`)
```powershell
.\.venv\Scripts\python.exe -m pytest -q
```
Expected: `2 passed`.

## Files
- `backend/app/main.py`: creates FastAPI application and registers routes
- `backend/app/api/routes/health.py`: health-check endpoint
- `backend/tests/test_health.py`: tests the health check and API schema
- `backend/requirements.txt`: dependency versions

## What is not implemented yet
Redis, PostgreSQL, Fluent Bit, event ingestion, rules, BERT, and response actions are deliberately not part of Module 1A. We will add them one at a time after this milestone passes.
