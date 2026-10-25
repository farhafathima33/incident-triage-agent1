        row=c.execute("SELECT request_hash,body FROM runs WHERE run_id=?",(rid,)).fetchone()
        if row:
            c.rollback()
            if row["request_hash"]!=h: return safe_error(409,"run_id_conflict")
            return response_state(json.loads(row["body"]))
        try: state=build_initial(body)
        except Exception as e:
            c.rollback(); return safe_error(422,"planning_failed")
        c.execute("INSERT INTO runs VALUES (?,?,?,?,?,?)",(rid,h,state["status"],canonical(state),now(),now())); c.commit()
        return response_state(state)
    finally: c.close()

@app.get("/v2/incidents/{run_id}")
def get_incident(run_id:str):
    c=db()
    try:
        row=c.execute("SELECT body FROM runs WHERE run_id=?",(run_id,)).fetchone()
        if not row:return safe_error(404,"not_found")
        return response_state(json.loads(row["body"]))
    finally:c.close()

@app.post("/v2/incidents/{run_id}/receipts")
async def post_receipts(run_id:str, request:Request):
    try: receipt=await request.json()
    except Exception:return safe_error(400,"invalid_json")
    if not isinstance(receipt,dict) or not isinstance(receipt.get("receiptId"),str) or not receipt["receiptId"]:return safe_error(422,"invalid_receipt")
    rh=digest(receipt); c=db()
    try:
        c.execute("BEGIN IMMEDIATE")
        row=c.execute("SELECT body FROM runs WHERE run_id=?",(run_id,)).fetchone()
        if not row:c.rollback();return safe_error(404,"not_found")
        state=json.loads(row["body"])
        prior=c.execute("SELECT body_hash FROM receipts WHERE run_id=? AND receipt_id=?",(run_id,receipt["receiptId"])).fetchone()
        if prior:
            c.rollback()
            if prior["body_hash"]!=rh:return safe_error(409,"receipt_id_conflict")
            return response_state(state)
        if state["status"]!="waiting":c.rollback();return safe_error(422,"invalid_state")
        pending={x["actionId"]:x for x in state.get("dispatches",[])}
        outcomes=receipt.get("outcomes",[]); approvals=receipt.get("approvals",[])
        if not isinstance(outcomes,list) or not isinstance(approvals,list) or (not outcomes and not approvals):c.rollback();return safe_error(422,"invalid_receipt")
        for outcome in outcomes:
            a=pending.get(outcome.get("actionId"))
            if not a or outcome.get("callId")!=a.get("callId") or outcome.get("attempt")!=a.get("attempt") or not isinstance(outcome.get("nonce"),str):c.rollback();return safe_error(422,"unknown_outcome")
            state["receiptLog"].append({"receiptId":receipt["receiptId"],"actionId":outcome["actionId"],"callId":outcome["callId"],"attempt":outcome["attempt"],"status":outcome.get("status"),"resultClass":outcome.get("resultClass"),"nonce":outcome["nonce"]})
            # Correlate each physical attempt with the authoritative receipt.
            internal_for_span = state.get("_internal", {})
            matching = next((x for x in internal_for_span.get("toolSpans", []) if x.get("actionId") == outcome["actionId"] and x.get("callId") == outcome["callId"] and x.get("attempt", 1) == outcome["attempt"]), None)
            if matching:
                client_span = find_span(state, matching.get("clientSpanId"))
                for key, value in (("ga5.receipt.id", receipt["receiptId"]), ("ga5.receipt.nonce", outcome["nonce"]), ("http.response.status_code", outcome.get("status"))):
                    set_span_attr(client_span, key, value)
                status = outcome.get("status")
                if status == 503 or (status == 0 and outcome.get("errorType") == "timeout"):
                    if client_span is not None: client_span["status"] = {"code": 2}
                    set_span_attr(client_span, "error.type", "503" if status == 503 else "timeout")
                elif isinstance(status, int) and 200 <= status < 300:
                    if client_span is not None: client_span["status"] = {"code": 1}
                if outcome.get("errorType") == "timeout": set_span_attr(client_span, "error.type", "timeout")
        state["dispatches"]=[]
        internal=state["_internal"]; req=internal["request"]
        # Only issue a single retry for a 503. Never issue dependent effects on timeout.
        retry=[]; timed_out=False; failed=False
        for outcome in outcomes:
            original=pending[outcome["actionId"]]
            if outcome.get("status")==503 and original.get("attempt")==1:
                new=dict(original); new["attempt"]=2
                clientspan=ident(8); execspan=next((x.get("execSpanId") for x in internal.get("toolSpans",[]) if x.get("actionId")==original["actionId"]), None)
                new["traceparent"]=f"00-{internal['traceId']}-{clientspan}-01"; retry.append(new)
                common={"ga5.run.id":run_id,"ga5.public.marker":req["publicMarker"],"ga5.action.id":original["actionId"],"ga5.attempt":2,"http.request.method":"POST","http.request.resend_count":1}
                spans=state["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
                spans.append(otlp_span(internal["traceId"],clientspan,execspan,"POST tool/"+original["toolName"],3,common,status=2))
                internal.setdefault("toolSpans",[]).append({"actionId":original["actionId"],"callId":original["callId"],"toolName":original["toolName"],"clientSpanId":clientspan,"attempt":2,"execSpanId":execspan})
            elif outcome.get("status")==0 and outcome.get("errorType")=="timeout": timed_out=True
            elif not (isinstance(outcome.get("status"),int) and 200<=outcome["status"]<300): failed=True
        if retry:
            state["dispatches"]=retry;state["status"]="waiting";state["actionLog"].extend(retry)
        elif timed_out or failed:
            state["status"]="failed";state["suppressed"]=["effect_not_dispatched_due_to_diagnostic_failure"]
        else:
            # Determine one permitted effect using diagnosis and tool catalog; destructive effects require approval.
            effects=set(req.get("policy",{}).get("effectTools",[])); catalog={t.get("name"):t for t in req.get("toolCatalog",[]) if isinstance(t,dict)}
            root=state["diagnosis"]["rootCause"].lower(); candidates=[]
            for name in effects:
                if name not in catalog:continue
                desc=(catalog[name].get("description","")+" "+name).lower()
                if "scale" in root and "limit" in root and ("page" in desc or "notify" in desc): candidates.append(name)
                elif any(w in root for w in ("capacity","traffic","load")) and "scale" in desc:candidates.append(name)
                elif "rollback" in root and "rollback" in desc:candidates.append(name)
                elif "feature" in root and "disable_feature" in name:candidates.append(name)
            if not candidates:
                # Safe fallback: page/notify owner if available, never scale at a limit.
                candidates=[n for n in effects if n in catalog and any(w in (n+" "+str(catalog[n].get("description",""))).lower() for w in ("page_owner","page owner","notify_owner","notify owner"))]
            if not candidates:
                state["status"]="failed";state["suppressed"]=["no_justified_effect_found"]
            else:
                chosen=sorted(candidates)[0]; args={}
                schema=catalog[chosen].get("inputSchema",{})
                for key, prop in schema.get("properties",{}).items():
                    if key in ("incidentId","incident_id"):args[key]=req["incident"].get("incidentId")
                    elif key in ("service","serviceName","service_name"):args[key]=req["incident"].get("service")
                    elif key in ("reason","message","summary"):args[key]="Incident triage action justified by stored diagnosis"
                    elif key in schema.get("required",[]):args[key]="incident-response"
                action_id=ident(8);call_id=ident(8)
                if chosen in req.get("policy",{}).get("approvalRequiredFor",[]):
                    approval_id=ident(8); gate=ident(8)
                    state["approvals"]=[{"approvalId":approval_id,"actionId":action_id,"toolName":chosen,"argumentsDigest":digest(args)}]
                    state["status"]="waiting";state["dispatches"]=[];internal["approvalPending"]={"approvalId":approval_id,"actionId":action_id,"toolName":chosen,"arguments":args,"callId":call_id}
                    spans=state["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
                    spans.append(otlp_span(internal["traceId"],gate,internal["agentSpanId"],"approval_gate",1,{"ga5.run.id":run_id,"ga5.public.marker":req["publicMarker"],"ga5.approval.id":approval_id}))
                else:
                    state["chosenEffect"]=chosen;state["dispatches"]=[{"actionId":action_id,"callId":call_id,"phase":"effect","toolName":chosen,"arguments":args,"evidence":state["diagnosis"]["evidence"][:1],"attempt":1,"traceparent":f"00-{internal['traceId']}-{ident(8)}-01"}];internal["effectPending"]=state["dispatches"][0];state["actionLog"].append(state["dispatches"][0])
        if approvals and internal.get("approvalPending"):
            ap=internal["approvalPending"]; got=next((x for x in approvals if x.get("approvalId")==ap["approvalId"]),None)
            if not got or got.get("decision")!="approved" or not isinstance(got.get("nonce"),str):c.rollback();return safe_error(422,"invalid_approval")
            state["receiptLog"].append({"receiptId":receipt["receiptId"],"approvalId":got["approvalId"],"decision":"approved","nonce":got["nonce"]})
            state["approvals"]=[];state["chosenEffect"]=ap["toolName"]
            dispatch={"actionId":ap["actionId"],"callId":ap["callId"],"phase":"effect","toolName":ap["toolName"],"arguments":ap["arguments"],"evidence":state["diagnosis"]["evidence"][:1],"attempt":1,"approvalId":ap["approvalId"],"approvalNonce":got["nonce"],"traceparent":f"00-{internal['traceId']}-{ident(8)}-01"}
            state["dispatches"]=[dispatch];internal["effectPending"]=dispatch;internal["approvalPending"]=None;state["actionLog"].append(dispatch)
        # A successful effect outcome completes the run; a failed effect terminates safely.
        if outcomes and all(x.get("phase")=="effect" for x in outcomes):
            state["status"]="completed" if all(isinstance(x.get("status"),int) and 200<=x["status"]<300 for x in outcomes) else "failed"
            state["dispatches"]=[]
        c.execute("INSERT INTO receipts VALUES (?,?,?)",(run_id,receipt["receiptId"],rh))
        state["_internal"]=internal
        c.execute("UPDATE runs SET state=?,body=?,updated=? WHERE run_id=?",(state["status"],canonical(state),now(),run_id));c.commit()
        return response_state(state)
    except Exception:
