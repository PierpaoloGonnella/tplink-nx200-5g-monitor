#!/usr/bin/env python3
"""
nx200_debug_login.py
---------------------------------------------------------------------------
Script di debug che usa una socket SSL raw per fare il login al modem
e MOSTRA esattamente cosa risponde, byte per byte, senza che requests/urllib3
interpretino la risposta.

Uso:
    python nx200_debug_login.py --host 192.168.1.1 --password TUA_PWD
"""

import argparse
import base64
import hashlib
import random
import re
import socket
import ssl
import sys


def rand_hex(n):
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def rsa_encrypt(message, n_hex, e_hex, chunk_size):
    from binascii import hexlify
    n = int(n_hex, 16)
    e = int(e_hex, 16)
    n_bytes = (n.bit_length() + 7) // 8
    msg_bytes = message.encode("utf-8")
    out_hex = []
    for i in range(0, len(msg_bytes), chunk_size):
        chunk = msg_bytes[i:i+chunk_size]
        padded = chunk + b"\x00" * (n_bytes - len(chunk))
        m = int.from_bytes(padded, "big")
        c = pow(m, e, n)
        h = format(c, "x")
        if len(h) % 2 == 1:
            h = "0" + h
        out_hex.append(h)
    return "".join(out_hex)


def aes_encrypt(key, iv, data):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))


def raw_post(host, port, path, headers_dict, body_bytes):
    """Manda una POST attraverso una socket SSL raw e ritorna i byte raw ricevuti."""
    sock = socket.create_connection((host, port), timeout=15)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ssock = ctx.wrap_socket(sock, server_hostname=host)

    request_lines = [f"POST {path} HTTP/1.1", f"Host: {host}"]
    for k, v in headers_dict.items():
        request_lines.append(f"{k}: {v}")
    request_lines.append(f"Content-Length: {len(body_bytes)}")
    request_lines.append("")
    request_lines.append("")
    request_head = "\r\n".join(request_lines).encode("utf-8")
    full_request = request_head + body_bytes

    print(f"\n>>> SENDING REQUEST ({len(full_request)} bytes) >>>")
    print(full_request.decode("utf-8", errors="replace")[:500])
    print("...")

    ssock.sendall(full_request)

    # Leggi tutta la risposta finche' la socket si chiude o timeout
    chunks = []
    try:
        while True:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    except (socket.timeout, ssl.SSLError) as e:
        print(f"\n[lettura terminata: {e}]")

    ssock.close()
    return b"".join(chunks)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", required=True, help="es. 192.168.1.1")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--password", required=True)
    p.add_argument("--username", default="admin")
    args = p.parse_args()

    # 1. Recupera chiavi RSA via getParm
    base = f"https://{args.host}:{args.port}"
    print(f"\n=== Step 1: POST {base}/cgi/getParm ===")
    import urllib3, urllib.request
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    # Gli stessi header che usa il browser, IL MODEM E' PIGNOLO su questi.
    browser_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/148.0.0.0 Safari/537.36",
        "Accept": "text/plain, */*; q=0.01",
        "Accept-Language": "it-IT,it;q=0.9",
        "Origin": base,
        "Referer": base + "/",
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "text/plain",
    }
    req = urllib.request.Request(f"{base}/cgi/getParm", method="POST",
                                  headers=browser_headers,
                                  data=b"")  # body vuoto ma esplicito
    parm_text = urllib.request.urlopen(req, context=ctx, timeout=10).read().decode()
    print(parm_text[:300])

    m_ee = re.search(r'ee\s*=\s*"([^"]+)"', parm_text)
    m_nn = re.search(r'nn\s*=\s*"([^"]+)"', parm_text)
    m_seq = re.search(r'seq\s*=\s*"?(\d+)"?', parm_text)
    if not (m_ee and m_nn and m_seq):
        print("ERRORE: impossibile parsare getParm")
        sys.exit(1)

    ee = m_ee.group(1)
    nn = m_nn.group(1)
    seq = int(m_seq.group(1))
    n_bytes = (int(nn, 16).bit_length() + 7) // 8
    print(f"\nModulus length: {n_bytes} bytes ({n_bytes*8} bits)")
    print(f"seq={seq}")

    # 2. Costruisci payload login
    aes_key = rand_hex(16)
    aes_iv = rand_hex(16)
    md5_hash = hashlib.md5(f"{args.username}{args.password}".encode()).hexdigest()

    # Body in chiaro - proviamo lo stesso formato del JS
    plain_body = (
        f'{{"data":{{"username":"{args.username}",'
        f'"password":"{args.password}"}},"operation":"cgi"}}\r\n'
    )
    encrypted = aes_encrypt(aes_key.encode(), aes_iv.encode(), plain_body.encode())
    data_b64 = base64.b64encode(encrypted).decode()

    sign_plain = f"key={aes_key}&iv={aes_iv}&h={md5_hash}&s={seq + len(data_b64)}"
    print(f"\nSign prepared ({len(sign_plain)} bytes; secrets hidden)")

    # Prova ogni chunk size, mostrando per ciascuno il response raw
    for cs in [n_bytes - 11, n_bytes - 1, n_bytes]:
        print(f"\n\n========== CHUNK SIZE = {cs} ==========")
        sign_hex = rsa_encrypt(sign_plain, nn, ee, cs)
        print(f"Sign cifrato (hex, {len(sign_hex)} chars): {sign_hex[:80]}...")

        body = f"sign={sign_hex}\r\ndata={data_b64}\r\n"
        body_bytes = body.encode()

        headers = {
            "Content-Type": "text/plain",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "text/plain, */*; q=0.01",
            "Accept-Language": "it-IT,it;q=0.9",
            "Origin": f"https://{args.host}",
            "Referer": f"https://{args.host}/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/148.0.0.0 Safari/537.36",
            "Connection": "keep-alive",
        }

        try:
            response = raw_post(args.host, args.port, "/cgi_gdpr?9",
                                 headers, body_bytes)
            print(f"\n<<< RAW RESPONSE ({len(response)} bytes) <<<")
            # Stampa primi byte come hex + come testo
            print("HEX (primi 200 byte):")
            print(response[:200].hex(" "))
            print("\nTESTO (primi 1000 byte):")
            print(response[:1000].decode("utf-8", errors="replace"))
            print("\n--- fine ---")
        except Exception as e:
            print(f"ERRORE durante POST: {e}")


if __name__ == "__main__":
    main()
