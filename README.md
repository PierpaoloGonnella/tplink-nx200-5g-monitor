# NX200 Monitor

[![tests](https://github.com/PierpaoloGonnella/tplink-nx200-5g-monitor/actions/workflows/tests.yml/badge.svg)](https://github.com/PierpaoloGonnella/tplink-nx200-5g-monitor/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Monitoraggio delle metriche radio **LTE / 5G NR** del modem **TP-Link Archer NX200**:
raccolta periodica in SQLite, dashboard Streamlit in tempo reale, analisi delle
tendenze e dei valori MCS/modulazione.

> Progetto indipendente, non affiliato a TP-Link. Usalo solo su apparati di tua proprietà.

## Caratteristiche

- **Raccolta affidabile**: login via Selenium, query tramite il client JavaScript
  nativo del firmware (`$.dm.getList` su `/cgi_gdpr?9`, JSON cifrato).
- **Dati validati**: risposte vuote, HTTP 406 o errori API non diventano campioni;
  finiscono nella tabella `poll_errors`.
- **Dashboard** (Streamlit, sola lettura): RSRP/SINR LTE e 5G, PCI, MCS e
  modulazioni nel tempo, avvisi di calo, export CSV.
- **Raccolta in background** con lock, arresto controllato, log a rotazione e SQLite WAL.
- **49 test offline**: nessun accesso al modem richiesto.

## Struttura

```
nx200_monitor_prod.py     Entrypoint del monitor (CLI)
nx200_monitor_v4.py       Collector e definizioni dei campi della cella servente
nx200_collection.py       Avvio/stato/arresto della raccolta in background
nx200_credentials.py      Lettura del file credenziali locale
nx200_radio_fields.py     Estrazione MCS / modulazione
nx200_dashboard.py        Dashboard Streamlit
nx200_dashboard_data.py   Accesso in sola lettura al database
nx200_analysis.py         Tendenze e avvisi RSRP/SINR
nx200_modulation.py       Timeline delle modulazioni
nx200_view_data.py        Visualizzazione, statistiche ed export da terminale
nx200_monitor.py          Client alternativo basato su tplinkrouterc6u
verify_modem.py           Verifica autenticata ripetibile sul modem reale
avvia_dashboard.ps1       Avvio rapido della dashboard su Windows
tests/                    Test unitari (unittest)
docs/                     Note sul protocollo e sulle verifiche
experiments/              Prototipi storici, non supportati
```

## Requisiti

- Python 3.11+
- Google Chrome (usato da Selenium per il login)
- Windows (testato); gli script Python sono portabili, `avvia_dashboard.ps1` è solo PowerShell.

## Installazione

```powershell
git clone https://github.com/PierpaoloGonnella/tplink-nx200-5g-monitor.git
cd tplink-nx200-5g-monitor
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

`requirements-optional.txt` serve per `nx200_monitor.py`, `experiments/nx200_monitor_lib.py` e per la suite di test.

## Credenziali

La password non va mai scritta nel codice. `nx200_monitor_prod.py` la cerca in quest'ordine:

1. `--password` (sconsigliato: resta visibile nell'elenco dei processi);
2. `--credentials-file`: file locale, es. `modem-access.local.json` (escluso da Git).
   Se presenti, `host` e `username` del file sostituiscono quelli da riga di comando;
3. variabile d'ambiente `NX200_PASSWORD`;
4. prompt interattivo, senza mostrare la password.

Formato del file credenziali:

   ```json
   { "host": "https://192.168.1.1", "username": "admin", "password": "..." }
   ```

   È accettato anche il formato a righe `host: valore` / `username: valore` / `password: valore`.

## Uso

```powershell
# Un singolo campione
python nx200_monitor_prod.py --host https://192.168.1.1 --once

# Polling continuo (minimo 10 s)
python nx200_monitor_prod.py --interval 60 --log monitor.log

# Statistiche ed export
python nx200_view_data.py --stats
python nx200_view_data.py --csv --csv-file results.csv
```

In modalità `--once` il codice di uscita è `0` dopo un campione valido, `1` in caso di errore.
Il polling continuo ricrea la sessione dopo un errore e riprova al ciclo successivo.

### Raccolta in background

```powershell
python nx200_collection.py start --interval 60
python nx200_collection.py status
python nx200_collection.py stop
```

Usa il file credenziali locale, scrive in `nx200_prod.db` e `collection.log`
(rotazione 5 MB × 3). Un lock impedisce avvii duplicati; `stop` chiude browser e
database dopo l'operazione corrente. Non è configurato l'avvio automatico al login.

### Dashboard

```powershell
python -m streamlit run nx200_dashboard.py
# oppure
.\avvia_dashboard.ps1 [-Database percorso.db]
```

Apri <http://localhost:8501>. La dashboard è in ascolto solo su `127.0.0.1`,
apre SQLite in sola lettura, non contatta il modem e non legge le credenziali.
Si aggiorna ogni 3 secondi; grafici ed export sono limitati agli ultimi 5000
campioni del periodo selezionato. Orari in Europe/Rome.

## Metriche

### Database

`samples`: timestamp UTC, tipo di rete, PCI, RSRP e SINR di entrambe le radio,
`nr_dl_mcs`, `nr_ul_mcs`, `lte_dl_mcs`, `lte_ul_mcs`, i corrispondenti `*_mod` e la
risposta JSON grezza. `0` è un valore valido, `NULL` indica un valore assente.
`poll_errors(ts, message)` raccoglie gli errori. Lo schema viene aggiornato
aggiungendo le colonne mancanti, senza riscrivere lo storico.

### MCS e modulazione

Indici MCS e stringhe di modulazione (QPSK, 16QAM, 64QAM, …) sono quelli dichiarati
dal modem per le sole celle attive, separati per download/upload e LTE/NR.
La modulazione non viene dedotta dall'indice. Per i campioni precedenti all'aggiunta
delle colonne, i valori sono ricostruiti dal JSON originale in sola lettura.
Ogni campione è un'istantanea: le variazioni tra due letture non sono registrate.

### Tendenze e avvisi

Mediana degli ultimi 10 minuti contro i 20 precedenti, per RSRP e SINR di ciascuna
radio, su mediane per minuto. Servono almeno 20 minuti continui sullo stesso PCI.
Cambi di PCI, radio assente, pause oltre tre intervalli (minimo 180 s) o dati
scaduti interrompono il confronto.

| | Andamento | Avviso di calo |
|---|---|---|
| RSRP | ±3 dB | −6 dB |
| SINR | ±2 dB | −4 dB |

Sono confronti descrittivi, non previsioni né diagnosi.

## Test

```powershell
python -m pip install -r requirements-optional.txt
python -m unittest discover -s tests -v
```

## Sicurezza e privacy

Non pubblicare database, log, dump HTML o file `*.local.json`: possono contenere
dati della SIM, della rete o della sessione. `.gitignore` li esclude, insieme alle
cartelle `local/` e `verification/`.

## Documentazione

- [docs/protocol.md](docs/protocol.md): trasporto del firmware e correzioni
- [docs/verification.md](docs/verification.md): verifiche eseguite sul modem reale
- [experiments/README.md](experiments/README.md): prototipi storici

## Licenza

[MIT](LICENSE)
