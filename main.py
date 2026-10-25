import os
import json
import sqlite3
import hashlib
import secrets
import re
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Body
from fastapi.responses import JSONResponse
from openai import OpenAI

app = FastAPI(title="Observable Incident Triage Agent", version="2.0")

DB_PATH = os.getenv("DB_PATH", "/tmp/incident_agent.sqlite3")
PROFILE = "ga5-incident-agent/v2"


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def ident(n=8):
    return secrets.token_hex(n)


def db():
    connection = sqlite3.connect(DB_PATH, timeout=20)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=20000")

    connection.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            request_hash TEXT NOT NULL,
            state TEXT NOT NULL,
            body TEXT NOT NULL,
            created TEXT NOT NULL,
            updated TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS receipts (
            run_id TEXT NOT NULL,
            receipt_id TEXT NOT NULL,
            body_hash TEXT NOT NULL,
            PRIMARY KEY (run_id, receipt_id)
        )
    """)

    connection.commit()
    return connection


def error_response(code, message):
    return JSONResponse(
        status_code=code,
        content={"error": message}
    )


def public_state(state):
    # Never return internal request data or sensitive information.
    return {
        key: value
        for key, value in state.items()
        if key != "_internal"
    }


def state_response(state):
    return JSONResponse(content=public_state(state))


def make_span(trace_id, span_id, parent_id, name, kind, attrs,
              status=0, links=None):
    attributes = []

    for key, value in attrs.items():
        if value is None:
            continue

        if isinstance(value, bool):
            encoded = {"boolValue": value}
        elif isinstance(value, int):
            encoded = {"intValue": value}
        elif isinstance(value, float):
            encoded = {"doubleValue": value}
        else:
            encoded = {"stringValue": str(value)}

        attributes.append({"key": key, "value": encoded})

    span = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": kind,
        "startTimeUnixNano": str(
            int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)
        ),
        "endTimeUnixNano": str(
            int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)
        ),
        "attributes": attributes,
        "status": {"code": status}
    }

    if parent_id:
        span["parentSpanId"] = parent_id

    if links:
        span["links"] = links

    return span


def get_spans(state):
    return state["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]


def update_span_attribute(span, key, value):
    if span is None or value is None:
        return

    for attribute in span.get("attributes", []):
        if attribute["key"] == key:
            if isinstance(value, int):
                attribute["value"] = {"intValue": value}
            else:
                attribute["value"] = {"stringValue": str(value)}
            return

    span.setdefault("attributes", []).append({
        "key": key,
        "value": (
            {"intValue": value}
            if isinstance(value, int)
            else {"stringValue": str(value)}
        )
    })


def find_span(state, span_id):
    for span in get_spans(state):
        if span.get("spanId") == span_id:
            return span
    return None


def get_trace_context(request, body):
    value = (
        request.headers.get("traceparent")
        or body.get("traceparent")
    )

    tracestate = (
        request.headers.get("tracestate")
        or body.get("tracestate")
    )

    match = re.fullmatch(
        r"00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})",
        value or ""
    )

    if (
        match
        and set(match.group(1)) != {"0"}
        and set(match.group(2)) != {"0"}
    ):
        return match.group(1), match.group(2), tracestate

    return ident(16), None, None
