#!/usr/bin/env python3
"""Test helper: a fake OIDC issuer (discovery + JWKS) and a token minter. Needs `pip install cryptography`.

  jwt_tool.py gen   <dir>                         create <dir>/key.pem
  jwt_tool.py serve <dir> <port> <issuer>         serve /.well-known/openid-configuration and /jwks
  jwt_tool.py jwks  <dir>                         print the public JWKS (for a "jwksFile" source)
  jwt_tool.py mint  <dir> <issuer> --sub S [--aud A] [--ttl SECONDS] [--age SECONDS_SINCE_ISSUED] [--kid K]
"""
import argparse, base64, json, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
load = lambda d: serialization.load_pem_private_key(open(f"{d}/key.pem", "rb").read(), None)
KID = "it-key-1"

def jwks(key):
    n = key.public_key().public_numbers()
    ib = lambda i: i.to_bytes((i.bit_length() + 7) // 8, "big")
    return {"keys": [{"kty": "RSA", "kid": KID, "use": "sig", "alg": "RS256", "n": b64(ib(n.n)), "e": b64(ib(n.e))}]}

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("cmd"); ap.add_argument("dir"); ap.add_argument("arg", nargs="*")
    ap.add_argument("--sub"); ap.add_argument("--aud", default="sonarqube"); ap.add_argument("--ttl", type=int, default=600)
    ap.add_argument("--age", type=int, default=0); ap.add_argument("--kid", default=KID)
    a = ap.parse_args()
    if a.cmd == "gen":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        open(f"{a.dir}/key.pem", "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    elif a.cmd == "serve":
        key, port, issuer = load(a.dir), int(a.arg[0]), a.arg[1]
        base = f"http://host.docker.internal:{port}"
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/.well-known/openid-configuration": body = {"issuer": issuer, "jwks_uri": base + "/jwks"}
                elif self.path == "/jwks": body = jwks(key)
                else: self.send_response(404); self.end_headers(); return
                data = json.dumps(body).encode(); self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(data)
            def log_message(self, *x): pass
        HTTPServer(("0.0.0.0", port), H).serve_forever()
    elif a.cmd == "jwks":
        print(json.dumps(jwks(load(a.dir))))
    elif a.cmd == "mint":
        key, issuer = load(a.dir), a.arg[0]
        now = int(time.time()) - a.age
        head = {"alg": "RS256", "typ": "JWT", "kid": a.kid}
        claims = {"iss": issuer, "sub": a.sub, "aud": [a.aud], "iat": now, "exp": now + a.ttl}
        signing = b64(json.dumps(head).encode()) + "." + b64(json.dumps(claims).encode())
        sig = key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
        print(signing + "." + b64(sig))
    else: sys.exit("unknown command")

main()
