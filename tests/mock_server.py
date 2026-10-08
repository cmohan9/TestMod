#!/usr/bin/env python3
"""Tiny mock of the CyberArk Identity token endpoint, Privilege Cloud REST API and Azure Blob PUT,
used only to exercise the PowerShell suite end-to-end without a tenant."""
import json, sys, re, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

STATE = {"platforms": {}, "safes": {}, "members": {}, "accounts": {}, "next": 100, "blobs": [], "log": []}
STATE["platforms"][1] = {"Id": 1, "general": {"id": "OCA_Windows_Desktop_local_acnt", "name": "Windows Desktop Local", "active": True}}
for _i, _pid in enumerate(["WinServerLocal", "WinDomain", "UnixSSH", "Oracle", "MSSql"], start=2):
    STATE["platforms"][_i] = {"Id": _i, "general": {"id": _pid, "name": _pid, "active": True}}
MISSING_GROUPS = set(a for a in sys.argv[2:] if not a.startswith("-")) if len(sys.argv) > 2 else set()
FAIL_BLOB = "--fail-blob" in sys.argv
KNOWN_GROUPS = {"Privilege Cloud Administrators", "Global-CyberArk-BGAccount"}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, obj=None, raw=None):
        body = raw if raw is not None else (json.dumps(obj).encode() if obj is not None else b"")
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def _body(self):
        n = int(self.headers.get("Content-Length", 0)); return self.rfile.read(n) if n else b""
    def _auth(self):
        return self.headers.get("Authorization", "") == "Bearer TESTTOKEN"
    def do_PUT(self):
        u = urlparse(self.path); data = self._body()
        if u.path.startswith("/blob/"):
            if FAIL_BLOB: return self._send(403, raw=b"<Error><Code>AuthenticationFailed</Code><Message>bad sas sig=abc</Message></Error>")
            STATE["blobs"].append((u.path, u.query, len(data))); return self._send(201)
        self._send(404, {})
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query); p = unquote(u.path)
        m = re.match(r"/__failblob/(\d)$", p)
        if m:
            global FAIL_BLOB; FAIL_BLOB = m.group(1) == "1"; return self._send(200, {"fail_blob": FAIL_BLOB})
        m = re.match(r"/__missing/(.+)/(\d)$", p)
        if m:
            (MISSING_GROUPS.add if m.group(2) == "1" else MISSING_GROUPS.discard)(m.group(1)); return self._send(200, {"missing": sorted(MISSING_GROUPS)})
        if p == "/__state": return self._send(200, {k: (list(v.values()) if isinstance(v, dict) else v) for k, v in STATE.items()})
        if not self._auth(): return self._send(401, {"ErrorCode": "X", "ErrorMessage": "unauthorized"})
        if p == "/api/Platforms/Targets":
            s = q.get("search", [""])[0].lower()
            L = [v for v in STATE["platforms"].values() if not s or s in v["general"]["id"].lower() or s in v["general"]["name"].lower()]
            return self._send(200, {"Platforms": L, "Total": len(L)})
        m = re.match(r"/api/Safes/([^/]+)/Members$", p)
        if m: return self._send(200, {"value": STATE["members"].get(m.group(1), [])})
        m = re.match(r"/api/Safes/([^/]+)$", p)
        if m:
            return self._send(200, STATE["safes"][m.group(1)]) if m.group(1) in STATE["safes"] else self._send(404, {"ErrorCode": "SFWS0007", "ErrorMessage": "Safe %s was not found." % m.group(1)})
        if p == "/api/Safes": return self._send(200, {"value": list(STATE["safes"].values())[:1], "count": len(STATE["safes"])})
        if p == "/api/Accounts":
            s = q.get("search", [""])[0].split(" ")
            L = [a for a in STATE["accounts"].values() if a["userName"] in s]
            return self._send(200, {"value": L, "count": len(L)})
        m = re.match(r"/api/Accounts/([^/]+)$", p)
        if m and m.group(1) in STATE["accounts"]:
            a = STATE["accounts"][m.group(1)]
            for f in ("lastVerifiedTime", "lastReconciledTime"):
                if a.get("_pending_" + f) and time.time() > a["_pending_" + f]:
                    a["secretManagement"][f] = int(time.time()); a["secretManagement"]["status"] = "success"; a.pop("_pending_" + f)
            return self._send(200, {k: v for k, v in a.items() if not k.startswith("_")})
        self._send(404, {"ErrorCode": "X", "ErrorMessage": "no route " + p})
    def do_POST(self):
        u = urlparse(self.path); p = unquote(u.path); data = self._body()
        if p == "/id/oauth2/platformtoken":
            f = parse_qs(data.decode())
            if f.get("client_secret", [""])[0] == "goodkey": return self._send(200, {"access_token": "TESTTOKEN", "expires_in": 900})
            return self._send(400, {"error": "invalid_client", "error_description": "bad creds"})
        if not self._auth(): return self._send(401, {"ErrorCode": "X", "ErrorMessage": "unauthorized"})
        j = json.loads(data) if data else {}
        STATE["log"].append([p, j])
        m = re.match(r"/api/Platforms/Targets/(\d+)/[Dd]uplicate/?$", p)
        if m:
            if "Name" not in j: return self._send(400, {"ErrorCode": "PASWS103E", "ErrorMessage": "Parameter [PlatformName] is missing"})
            STATE["next"] += 1; i = STATE["next"]
            STATE["platforms"][i] = {"Id": i, "general": {"id": j["Name"].replace(" ", ""), "name": j["Name"], "active": False, "description": j.get("Description")}}
            return self._send(201, {"ID": i, "PlatformID": j["Name"].replace(" ", ""), "Name": j["Name"], "Description": j.get("Description", "")})
        m = re.match(r"/api/Platforms/Targets/(\d+)/activate/?$", p)
        if m: STATE["platforms"][int(m.group(1))]["general"]["active"] = True; return self._send(200)
        if p == "/api/Safes":
            if j.get("managingCPM", "") not in ("", "PasswordManager_OCA"):
                return self._send(400, {"ErrorCode": "PASWS167E", "ErrorMessage": "There are some invalid parameters"})
            if j["safeName"] in STATE["safes"]: return self._send(409, {"ErrorCode": "SFWS0002", "ErrorMessage": "exists"})
            STATE["safes"][j["safeName"]] = j; STATE["members"][j["safeName"]] = []; return self._send(201, j)
        m = re.match(r"/api/Safes/([^/]+)/Members$", p)
        if m:
            n = j["memberName"]
            if n in MISSING_GROUPS or (n not in KNOWN_GROUPS and not n.startswith("Global-S") ) or (n.startswith("Global-S") and n in MISSING_GROUPS):
                return self._send(404, {"ErrorCode": "SFWS0010", "ErrorMessage": "Member %s has not been defined." % n})
            if any(x["memberName"] == n for x in STATE["members"][m.group(1)]): return self._send(409, {"ErrorCode": "SFWS0002", "ErrorMessage": "already member"})
            STATE["members"][m.group(1)].append(j); return self._send(201, j)
        if p == "/api/Accounts":
            if j["safeName"] not in STATE["safes"]: return self._send(404, {"ErrorCode": "SFWS0007", "ErrorMessage": "safe missing"})
            if not any(v["general"]["id"] == j["platformId"] for v in STATE["platforms"].values()): return self._send(400, {"ErrorCode": "PASWS", "ErrorMessage": "platform not found"})
            pap = j.get("platformAccountProperties", {})
            if "Description" in pap and "--reject-desc" in sys.argv: return self._send(400, {"ErrorCode": "PASWS", "ErrorMessage": "Property Description is not defined"})
            STATE["next"] += 1; i = "77_%d" % STATE["next"]
            a = dict(j); a.pop("secret", None); a["id"] = i; a["secretManagement"] = dict(j.get("secretManagement", {})); STATE["accounts"][i] = a
            a["_has_secret"] = "secret" in j
            return self._send(201, {k: v for k, v in a.items() if not k.startswith("_")})
        m = re.match(r"/api/Accounts/([^/]+)/(Verify|Reconcile)$", p)
        if m:
            f = "lastVerifiedTime" if m.group(2) == "Verify" else "lastReconciledTime"
            STATE["accounts"][m.group(1)]["_pending_" + f] = time.time() + 1; return self._send(200)
        self._send(404, {"ErrorCode": "X", "ErrorMessage": "no route " + p})

if __name__ == "__main__":
    port = int(sys.argv[1]); ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
