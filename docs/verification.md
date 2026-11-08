# Verifiche delle correzioni

- 49 test automatici superati: polling singolo/continuo, retry, timeout,
  errori HTTP e applicativi, chiusura risorse, parsing, valori zero,
  migrazione schema e compatibilita dell'output Windows.
- Test JavaScript del proxy JSON: successo, errore, bridge assente e timeout.
- Migrazioni verificate su copie di entrambi i database presenti.
- Login reale riuscito con le credenziali locali dell'utente.
- Un campione singolo e tre poll consecutivi sulla stessa sessione riusciti.
- Tre campioni continui con metriche NR e LTE presenti, zero errori.
- Visualizzazione, statistiche ed esportazione CSV dei tre campioni riuscite.
- Dipendenze controllate con pip check: nessun conflitto.
- Database originali invariati nel contenuto: 22 e 5 campioni rispettivamente.

Il firmware usa il proxy `$.dm.getList`, payload JSON cifrato e `/cgi_gdpr?9`.
Le vecchie chiamate testuali o in chiaro non erano compatibili.
Il codice principale verificato e `nx200_monitor_prod.py`; gli altri prototipi
restano sperimentali, come specificato nel README.

Artefatti locali delle prove: `verification/nx200_live.db`,
`verification/nx200_continuous.db`, `verification/continuous.csv`
e `verification/continuous.log`. La directory e esclusa da Git.
Non e stato lasciato un monitor in esecuzione.

Dashboard realtime verificata con Streamlit AppTest: rendering di grafici e
metriche, nuovi campioni dopo un commit, valori zero, compatibilita degli
schemi, dati scaduti, database vuoto e percorso inesistente. Nessun server
Streamlit e stato lasciato in esecuzione. La dashboard non accede al modem.

## Tendenze e raccolta prolungata

- Confronti descrittivi per minuto verificati su dati sintetici stabili,
  in miglioramento e in calo, con corretta gestione di zero, dati futuri,
  cambi di PCI, radio assente, pause e campioni scaduti.
- Avviso di calo verificato anche nella dashboard tramite AppTest.
- Avvio/arresto del worker e rilascio del lock verificati tra processi separati,
  senza accesso al modem durante i test.
- Credenziali locali supportate anche dal monitor principale, senza password
  nella riga di comando. Log ruotati e database WAL con indice temporale.
- La raccolta reale e stata avviata in background a intervalli di 60 secondi.
  I nuovi campioni vengono aggiunti al database di produzione, non a quelli
  di verifica. La dashboard gia in esecuzione legge gli stessi dati.
- Non e stato configurato un riavvio automatico al login di Windows.

Per lo stato corrente usare `nx200_collection.py status`; il PID e i conteggi
in questo documento non vengono congelati perche cambiano durante la raccolta.

## MCS e modulazione

Campi downMCS, upMCS, downlinkModType e uplinkModType confermati nelle
risposte reali del modem per LTE e 5G attivi. Colonne dedicate aggiunte in
modo compatibile; recupero dello storico dal JSON in sola lettura.
Test aggiuntivi: MCS zero, celle inattive escluse, campi non disponibili,
salvataggio, recupero dei vecchi campioni, tabella e grafici in dashboard.
Raccoglitore riavviato con database e intervallo precedenti.

## Grafici delle modulazioni

Quattro timeline categoriche automatiche LTE/5G, download/upload. Test per
interruzioni su pause, valori assenti e cambi PCI, mantenimento di etichette
firmware sconosciute, ordinamento coerente e aggiornamento dopo nuovi commit.
Rendering verificato anche sul database reale. Nessuna modifica al processo
di raccolta necessaria per questi grafici.
