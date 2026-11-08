# Protocollo e correzioni

La guida aggiornata e [README.md](../README.md).

Il vecchio monitor definito production non eseguiva polling continuo,
non normalizzava le metriche e salvava HTTP 406 come campione riuscito.
Questi comportamenti sono stati corretti e coperti da test offline.

La verifica sul modem ha identificato il trasporto effettivo: JSON cifrato
su `/cgi_gdpr?9`. Il monitor usa `$.dm.getList`, come la dashboard, e lascia
al proxy nativo token, ripristino delle chiavi, cifratura e decifratura.
Il percorso legacy `$.act`/`$.exe` e il payload testuale non sono adatti
al firmware verificato. Non serve modificare il firmware del modem.

Login e acquisizione simultanea delle metriche LTE/5G sono stati verificati.
Le prove usano database separati nella directory `verification/`; i database
originali restano invariati. I test automatici non richiedono accesso al modem.
