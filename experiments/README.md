# Esperimenti storici

Prototipi sviluppati durante il reverse engineering del firmware NX200.
**Non sono entrypoint supportati** e non sono coperti dai test: sono
conservati come riferimento sul protocollo.

| Script | Approccio |
|---|---|
| `nx200_monitor_v2.py`, `nx200_monitor_v3.py` | Client HTTP con cifratura AES/RSA lato Python |
| `nx200_monitor_hybrid.py` | Login via browser + query su socket |
| `nx200_monitor_selenium.py` | Scraping completo via Selenium |
| `nx200_monitor_html.py` | Lettura dal DOM della pagina di stato |
| `nx200_monitor_final.py`, `_simple.py`, `_working.py`, `_http_login.py` | Varianti basate su `nx200_monitor_v4` |
| `nx200_monitor_lib.py` | Libreria `tplinkrouterc6u` (vedi `requirements-optional.txt`) |
| `nx200_debug_login.py`, `nx200_discover.py` | Diagnostica login e scoperta endpoint |
| `nx200_tail_log.py` | Tail del log del monitor |

Gli script che importano moduli della radice aggiungono la radice al
`sys.path`, quindi si possono lanciare da qualsiasi cartella.
