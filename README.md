# Observable Incident Triage Agent

FastAPI implementation for `ga5-incident-agent/v2`.

## Run locally

```bash
pip install -r requirements.txt
export AIPIPE_TOKEN='your-token'
uvicorn main:app --host 0.0.0.0 --port 8000
```

Routes: `POST /v2/incidents`, `POST /v2/incidents/{runId}/receipts`, `GET /v2/incidents/{runId}`.

Set `AIPIPE_TOKEN` in Render environment variables. Do not commit credentials.
