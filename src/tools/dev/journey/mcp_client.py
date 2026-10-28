"""Minimal streamable-HTTP MCP client for the local Styx journey.

usage: mcp_client.py GATEWAY_ROOT URL CA_FILE list
       mcp_client.py GATEWAY_ROOT URL CA_FILE call TOOL JSON_ARGS
The bearer is read from GATEWAY_ROOT/gateway-model.token and never printed.
"""
import json, ssl, sys, urllib.request

root, url, ca, cmd = sys.argv[1:5]
token = open(f"{root}/gateway-model.token", "rb").read().strip().decode()
ctx = ssl.create_default_context(cafile=ca)
endpoint = url.rstrip("/") + "/mcp"
session = None
next_id = 0


def post(body, notify=False):
    global session, next_id
    if not notify:
        next_id += 1
        body["id"] = next_id
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-06-18",
    }
    if session:
        headers["Mcp-Session-Id"] = session
    req = urllib.request.Request(endpoint, json.dumps(body).encode(), headers, method="POST")
    with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
        session = resp.headers.get("Mcp-Session-Id", session)
        raw = resp.read().decode()
    if notify or not raw.strip():
        return None
    if resp.headers.get("Content-Type", "").startswith("text/event-stream"):
        for line in raw.splitlines():
            if line.startswith("data:"):
                msg = json.loads(line[5:])
                if msg.get("id") == body["id"]:
                    return msg
        raise RuntimeError("no response event")
    return json.loads(raw)


def close():
    if session:
        req = urllib.request.Request(endpoint, headers={"Authorization": "Bearer " + token, "Mcp-Session-Id": session}, method="DELETE")
        try:
            urllib.request.urlopen(req, context=ctx, timeout=30).read()
        except Exception as error:  # report, never retry
            print(json.dumps({"session_delete_error": str(error)}), file=sys.stderr)


try:
    init = post({"jsonrpc": "2.0", "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "styx-linux-journey", "version": "1"}}})
    post({"jsonrpc": "2.0", "method": "notifications/initialized"}, notify=True)
    if cmd == "list":
        tools = post({"jsonrpc": "2.0", "method": "tools/list", "params": {}})
        print(json.dumps([t["name"] for t in tools["result"]["tools"]]))
    elif cmd == "call":
        result = post({"jsonrpc": "2.0", "method": "tools/call", "params": {
            "name": sys.argv[5], "arguments": json.loads(sys.argv[6])}})
        print(json.dumps(result))
finally:
    close()
