#!/usr/bin/env python3
"""
nx200_monitor_http_login.py - Login via HTTP diretta, senza Selenium
"""

import sys as _sys, pathlib as _pl; _sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))
from nx200_monitor_v4 import RawHttpsClient, _aes_encrypt, _aes_decrypt, _rsa_encrypt, _rand_hex
import argparse
import logging
import sys
import base64
import hashlib
import re
import json
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger()

def do_login(host: str, username: str, password: str):
    """Login via POST HTTP diretta al /cgi_gdpr?9"""
    http = RawHttpsClient(host)
    
    log.info("Step 1: recupero chiavi RSA...")
    status, _, body = http.post("/cgi/getParm", b"")
    if status != 200:
        raise RuntimeError(f"getParm HTTP {status}")
    
    text = body.decode("utf-8", errors="replace")
    m_ee = re.search(r'ee\s*=\s*"([^"]+)"', text)
    m_nn = re.search(r'nn\s*=\s*"([^"]+)"', text)
    m_seq = re.search(r'seq\s*=\s*"?(\d+)"?', text)
    
    if not (m_ee and m_nn and m_seq):
        raise RuntimeError("Cannot parse RSA parameters")
    
    rsa_e = m_ee.group(1)
    rsa_n = m_nn.group(1)
    rsa_seq = int(m_seq.group(1))
    
    log.info("RSA OK, seq=%d", rsa_seq)
    
    # Step 2: genera chiavi AES
    aes_key_str = _rand_hex(16)
    aes_iv_str = _rand_hex(16)
    aes_key = aes_key_str.encode("ascii")
    aes_iv = aes_iv_str.encode("ascii")
    md5_hash_pw = hashlib.md5(f"{username}{password}".encode()).hexdigest()
    
    log.info("Step 2: invio login cifrato...")
    
    # Step 3: cripta il body di login
    plain_body = (
        f"8\r\n"
        f"[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\n"
        f"username={username}\r\n"
        f"password={password}\r\n"
    )
    
    encrypted = _aes_encrypt(aes_key, aes_iv, plain_body.encode())
    data_b64 = base64.b64encode(encrypted).decode()
    
    # Step 4: genera signature
    sign_plain = f"key={aes_key_str}&iv={aes_iv_str}&h={md5_hash_pw}&s={rsa_seq + len(data_b64)}"
    sign_hex = _rsa_encrypt(sign_plain, rsa_n, rsa_e)
    
    # Step 5: invia login
    body_bytes = f"sign={sign_hex}\r\ndata={data_b64}\r\n".encode()
    status, _hdrs, resp_body = http.post(
        "/cgi_gdpr?9", body_bytes,
        extra_headers={"Content-Type": "text/plain", "TokenID": ""}
    )
    
    if not resp_body:
        raise RuntimeError(f"Login: risposta vuota (HTTP {status})")
    
    # Step 6: decifra la risposta
    try:
        decoded = base64.b64decode(resp_body)
        decrypted = _aes_decrypt(aes_key, aes_iv, decoded).decode("utf-8", errors="replace")
        log.debug("Risposta login: %s", decrypted[:300])
    except Exception as e:
        raise RuntimeError(f"Cannot decrypt login response: {e}") from e
    
    # Step 7: verifica il risultato
    try:
        obj = json.loads(decrypted)
        if obj.get("success"):
            log.info("Login OK")
            jsessionid = http.cookies.get("JSESSIONID", "?")
            log.info("Session cookie acquired")
            return http, jsessionid
        else:
            raise RuntimeError(f"Login failed: errorcode={obj.get('errorcode')}")
    except json.JSONDecodeError:
        pass
    
    # Fallback: controllare $.ret
    m = re.search(r"\$\.ret\s*=\s*(\d+)", decrypted)
    if m and m.group(1) == "0":
        log.info("Login OK ($.ret=0)")
        return http, http.cookies.get("JSESSIONID", "?")
    
    raise RuntimeError(f"Login failed. Response: {decrypted[:300]}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="https://192.168.1.1")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    
    try:
        log.info("Connessione al modem...")
        http, jsessionid = do_login(args.host, args.username, args.password)
        log.info("Login completato")
        
        # Step 3: testa una query GDPR
        log.info("Prova query GDPR...")
        query = "5\r\n[DEV2_LTE_SERVING_CELL_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nPCI\r\nnetworkType\r\n"
        status, _, resp = http.post("/cgi_gdpr?9", query.encode())
        log.info("GDPR response HTTP %d: %r", status, resp[:200])
        
    except Exception as e:
        log.error("Errore: %s", e, exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
