#!/usr/bin/env python3
"""
nx200_discover.py
---------------------------------------------------------------------------
Esplora gli endpoint CGI del TP-Link Archer NX200 per scoprire dove sono
esposti i dati 5G NR sul tuo specifico firmware.

Strategia:
  1. Usa tplinkrouterc6u SOLO per il login (la cifratura RSA/AES e' l'unica
     parte che vogliamo riutilizzare).
  2. Una volta ottenuto lo stok/token, fa richieste raw a una lista di
     endpoint candidati e salva le risposte.
  3. Stampa un riassunto di cosa risponde ciascuno, evidenziando i campi
     che sembrano radio (rsrp/sinr/pci/...).

Uso:
    python nx200_discover.py --host http://192.168.1.1 --password TUA_PWD
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any

try:
    from tplinkrouterc6u import TplinkRouterProvider
except ImportError:
    print("ERRORE: pip install tplinkrouterc6u", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("discover")


# Endpoint/form name candidati. I firmware NX200 usano un sottoinsieme
# di questi nomi; alcuni sono in stile "form" (per la lib c6u), altri
# sono path luci/CGI diretti.
CANDIDATE_FORMS = [
    "mobile_status",
    "lte_status",
    "nr_status",
    "5g_status",
    "wan_status",
    "wan",
    "status",
    "internet_status",
    "network_status",
    "sim_status",
    "lan_ipv4_status",
    "performance",
    "system_status",
    "device_info",
    "lte_network_settings",
    "mobile_network",
    "cell_info",
    "signal_strength",
]

# Path HTTP diretti (alcuni firmware espongono /cgi-bin/luci/...)
CANDIDATE_PATHS = [
    "/cgi-bin/luci/;stok={stok}/admin/network/mobile_status",
    "/cgi-bin/luci/;stok={stok}/admin/network/lte_status",
    "/cgi-bin/luci/;stok={stok}/admin/network/wan_status",
    "/cgi-bin/luci/;stok={stok}/admin/status",
]


# Campi che ci interessano - se compaiono in una risposta, e' bingo.
RADIO_HINTS = re.compile(
    r"rsrp|rsrq|sinr|snr|pci|cell|earfcn|arfcn|cqi|mcs|tx_power|tx_pwr|"
    r"band|rbs|ri\b|modulation|signal|imei|imsi|iccid",
    re.IGNORECASE,
)


def find_radio_fields(obj: Any, path: str = "") -> list[tuple[str, Any]]:
    """Cerca ricorsivamente chiavi che sembrano dati radio nel JSON."""
    hits: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_path = f"{path}.{k}" if path else k
            if isinstance(k, str) and RADIO_HINTS.search(k):
                # mostra solo valori "semplici"; per dict/list mette un placeholder
                if isinstance(v, (str, int, float, bool)) or v is None:
                    hits.append((key_path, v))
                else:
                    hits.append((key_path, f"<{type(v).__name__}>"))
            hits.extend(find_radio_fields(v, key_path))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            hits.extend(find_radio_fields(item, f"{path}[{i}]"))
    return hits


def try_form(router: Any, form: str) -> tuple[bool, Any]:
    """Prova a richiedere un form name usando i metodi interni della libreria."""
    last_err = None
    for method_name in ("request", "_request_pwd", "_request_module"):
        method = getattr(router, method_name, None)
        if method is None:
            continue
        try:
            # firme diverse a seconda della versione lib
            try:
                data = method(form, {})
            except TypeError:
                data = method(form)
            return True, data
        except Exception as e:  # noqa: BLE001
            last_err = e
            continue
    return False, last_err


def try_http_path(router: Any, path_template: str) -> tuple[bool, Any]:
    """
    Prova una GET HTTP diretta usando la sessione requests interna alla libreria
    (se accessibile). Cerca attributi noti dove e' tipicamente salvata.
    """
    # Cerca la sessione e lo stok in vari posti possibili
    session = None
    stok = None
    host = None
    for attr in ("_session", "session", "_request_session"):
        s = getattr(router, attr, None)
        if s is not None and hasattr(s, "get"):
            session = s
            break
    for attr in ("_stok", "stok", "_token"):
        v = getattr(router, attr, None)
        if v:
            stok = v
            break
    for attr in ("host", "_host", "_url"):
        v = getattr(router, attr, None)
        if v:
            host = v
            break

    if not session or not host:
        return False, "session/host non accessibili dalla libreria"

    url = host.rstrip("/") + path_template.format(stok=stok or "")
    try:
        r = session.get(url, timeout=10)
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        try:
            return True, r.json()
        except ValueError:
            return True, r.text[:2000]  # tronchiamo per leggibilita'
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--username", default="admin")
    p.add_argument("--out", default="nx200_discovery.json",
                   help="File dove salvare il dump completo")
    args = p.parse_args()

    log.info("Login su %s ...", args.host)
    router = TplinkRouterProvider.get_client(args.host, args.password, args.username, log)
    router.authorize()

    results: dict[str, Any] = {
        "host": args.host,
        "router_class": type(router).__name__,
        "router_attrs": sorted(a for a in dir(router) if not a.startswith("__")),
        "forms": {},
        "paths": {},
    }

    try:
        # 1. Prova i form names
        for form in CANDIDATE_FORMS:
            ok, data = try_form(router, form)
            entry: dict[str, Any] = {"ok": ok}
            if ok:
                entry["data"] = data
                hits = find_radio_fields(data)
                entry["radio_field_hits"] = [
                    {"path": p, "value": v} for p, v in hits
                ]
                log.info("FORM %-30s OK   campi radio: %d", form, len(hits))
                for p, v in hits[:8]:
                    log.info("    %s = %r", p, v)
            else:
                entry["error"] = str(data)
                log.debug("FORM %-30s FAIL %s", form, data)
            results["forms"][form] = entry

        # 2. Prova i path HTTP diretti
        for path in CANDIDATE_PATHS:
            ok, data = try_http_path(router, path)
            entry = {"ok": ok}
            if ok:
                entry["data"] = data
                hits = find_radio_fields(data) if isinstance(data, (dict, list)) else []
                entry["radio_field_hits"] = [
                    {"path": pth, "value": v} for pth, v in hits
                ]
                log.info("PATH %-60s OK   campi radio: %d", path, len(hits))
            else:
                entry["error"] = str(data)
                log.debug("PATH %-60s FAIL %s", path, data)
            results["paths"][path] = entry

    finally:
        try:
            router.logout()
        except Exception:
            pass

    Path(args.out).write_text(json.dumps(results, indent=2, default=str),
                              encoding="utf-8")
    log.info("Dump completo salvato in %s", args.out)

    # Riassunto finale
    print("\n" + "=" * 70)
    print("RIASSUNTO")
    print("=" * 70)
    winners = [
        (name, len(e.get("radio_field_hits", [])))
        for name, e in {**results["forms"], **results["paths"]}.items()
        if e.get("ok") and e.get("radio_field_hits")
    ]
    winners.sort(key=lambda x: -x[1])
    if winners:
        print("Endpoint che espongono dati radio (ordinati per ricchezza):")
        for name, n in winners:
            print(f"  [{n:3d} campi]  {name}")
        print(f"\nApri {args.out} e guarda i 'radio_field_hits' del migliore.")
    else:
        print("Nessun endpoint candidato ha restituito campi radio.")
        print(f"Apri {args.out} per ispezionare comunque le risposte.")


if __name__ == "__main__":
    main()
