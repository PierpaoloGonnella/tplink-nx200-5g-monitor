"""Dashboard locale NX200: solo lettura, aggiornamento automatico."""
import os
import sqlite3
from pathlib import Path
import altair as alt
import pandas as pd
import streamlit as st
from nx200_dashboard_data import load_snapshot
from nx200_analysis import analyse_radio
from nx200_modulation import modulation_timeline, modulation_order

ROOT = Path(__file__).resolve().parent
st.set_page_config(page_title='NX200 · Segnale live', page_icon=':material/network_cell:', layout='wide')
st.title('NX200 · Segnale live')
st.caption('Segnali LTE e 5G, storico e stato della raccolta in un’unica vista.')

with st.sidebar:
    st.subheader('Visualizzazione')
    source = st.segmented_control('Origine dei dati', ['Monitor', 'Verifica'], default='Monitor')
    default_db = os.environ.get('NX200_DASHBOARD_DB', str(ROOT / 'nx200_prod.db'))
    if source == 'Verifica':
        default_db = str(ROOT / 'verification' / 'nx200_continuous.db')
    db_path = st.text_input('Database', value=default_db, key='db_' + str(source))
    period = st.segmented_control('Storico', ['1 h', '6 h', '24 h', '7 g', 'Tutto'], default='24 h')
    automatic = st.toggle('Aggiornamento automatico', value=True)
    expected_interval = st.number_input('Intervallo del monitor (secondi)', min_value=10, max_value=3600, value=60, step=10)
    st.caption('La vista si aggiorna ogni 3 secondi. I nuovi campioni arrivano alla frequenza impostata nel monitor.')
    st.divider()
    st.caption('Per raccogliere nuovi dati, lascia aperto il monitor in un altro terminale.')
    st.code('.\\.venv-review\\Scripts\\python.exe nx200_monitor_prod.py --interval 60', language='powershell')


@st.cache_data(ttl=2, max_entries=8, show_spinner=False)
def read_data(path, hours):
    return load_snapshot(path, hours=hours)


def chart(frame, names, title, unit, discrete=False):
    with st.container(border=True):
        st.subheader(title)
        data = frame[['ts', *names]].rename(columns=names).melt('ts', var_name='Radio', value_name=unit)
        if data[unit].notna().sum() == 0:
            st.info('Nessuna misura disponibile per questo grafico.')
            return
        plot = alt.Chart(data).mark_line(point=True, interpolate='step-after' if discrete else 'linear').encode(
            x=alt.X('ts:T', title='Ora', axis=alt.Axis(format='%H:%M')),
            y=alt.Y(f'{unit}:Q', title=unit, scale=alt.Scale(zero=discrete),
                    axis=alt.Axis(tickMinStep=1) if discrete else alt.Axis()),
            color=alt.Color('Radio:N', scale=alt.Scale(domain=['5G NR', 'LTE'], range=['#2dd4bf', '#60a5fa'])),
            tooltip=[alt.Tooltip('ts:T', title='Ora', format='%d/%m %H:%M:%S'), 'Radio:N', alt.Tooltip(f'{unit}:Q', format='.0f' if discrete else '.1f')],
        ).properties(height=270).interactive()
        st.altair_chart(plot, width='stretch', alt=title + ' per LTE e 5G nel periodo selezionato')


def modulation_chart(frame, radio, direction, title, levels):
    with st.container(border=True):
        st.subheader(title)
        data = modulation_timeline(frame, f'{radio}_{direction}_mod', f'{radio}_pci', expected_interval)
        if data.empty:
            st.info('Modulazione non disponibile nel periodo selezionato.')
            return
        plot = alt.Chart(data).mark_line(
            interpolate='step-after', point=True, color='#2dd4bf' if radio == 'nr' else '#60a5fa',
        ).encode(
            x=alt.X('ts:T', title='Ora', axis=alt.Axis(format='%H:%M')),
            y=alt.Y('Modulazione:O', title=None, sort=levels),
            detail='Segmento:N',
            tooltip=['Ora locale:N', 'Modulazione:N', alt.Tooltip('PCI:Q', format='.0f')],
        ).properties(height=220).interactive(bind_y=False)
        st.altair_chart(plot, width='stretch', alt=title + ' nel tempo, con interruzioni dove mancano dati')


@st.fragment(run_every=3 if automatic else None)
def live_view():
    if source == 'Verifica':
        st.info('Stai visualizzando i campioni salvati durante la verifica sul modem. Questa origine non raccoglie nuove misure.')
    try:
        snapshot = read_data(db_path, {'1 h': 1, '6 h': 6, '24 h': 24, '7 g': 168}.get(period))
    except (FileNotFoundError, ValueError) as error:
        st.info(str(error))
        return
    except (sqlite3.Error, pd.errors.DatabaseError):
        st.warning('Database non leggibile o temporaneamente occupato. Controlla il percorso; la vista riproverà al prossimo aggiornamento.')
        return
    frame, latest = snapshot['samples'], snapshot['latest']
    if latest.empty:
        st.warning('Non sono ancora presenti campioni con metriche radio valide. Avvia il monitor; eventuali vecchie risposte di errore non sono mostrate come misure.')
    else:
        sample = latest.iloc[0]
        timestamp = sample['ts']
        if pd.isna(timestamp):
            st.warning('La data dell’ultimo campione non è valida.')
        else:
            age = max(0, (pd.Timestamp.now(tz='UTC') - timestamp).total_seconds())
            when = timestamp.tz_convert('Europe/Rome').strftime('%d/%m/%Y %H:%M:%S %Z')
            text = f'Ultimo campione: {when} · {int(age)} secondi fa'
            if age > max(30, expected_interval * 3):
                st.warning('Dati non aggiornati. ' + text + '. Controlla che il monitor sia in esecuzione.')
            else:
                st.success('Raccolta recente · ' + text)
        with st.container(horizontal=True):
            for label, name, unit in [('5G · RSRP', 'nr_rsrp', 'dBm'), ('5G · SINR', 'nr_sinr', 'dB'),
                                      ('LTE · RSRP', 'lte_rsrp', 'dBm'), ('LTE · SINR', 'lte_sinr', 'dB')]:
                value = sample[name]
                st.metric(label, '—' if pd.isna(value) else f'{value:.1f} {unit}', border=True)
        def pci(name):
            return '—' if pd.isna(sample[name]) else str(int(sample[name]))
        st.caption(f"Rete: {sample['network_type'] or '—'} · PCI 5G: {pci('nr_pci')} · PCI LTE: {pci('lte_pci')} · Orari Europe/Rome")
        st.subheader('MCS e modulazione')
        def link_value(name):
            value = sample[name]
            if pd.isna(value):
                return 'Non disponibile'
            return str(int(value)) if name.endswith('_mcs') else str(value)
        links = [{'Radio': label, 'MCS download': link_value(f'{radio}_dl_mcs'),
                  'Modulazione download': link_value(f'{radio}_dl_mod'),
                  'MCS upload': link_value(f'{radio}_ul_mcs'),
                  'Modulazione upload': link_value(f'{radio}_ul_mod')}
                 for radio, label in [('nr', '5G NR'), ('lte', 'LTE')]]
        st.dataframe(pd.DataFrame(links), hide_index=True, alt='MCS e modulazione di download e upload delle radio attive')
        st.caption('Valori dichiarati dal modem per le celle attive nell’ultimo campione. MCS 0 è valido. La modulazione viene letta dal firmware; il code rate non viene ricostruito dall’indice MCS. Con un campione al minuto non vengono registrate tutte le variazioni tra due letture.')
    if not frame.empty:
        st.subheader('Modulazioni nel tempo')
        st.caption('Aggiornamento automatico ogni 3 secondi quando attivo. Ogni punto è una lettura del modem; i tratti a gradini collegano i campioni. Pause, valori mancanti e cambi di PCI interrompono le linee.')
        levels = modulation_order(frame)
        for radio, label in [('nr', '5G'), ('lte', 'LTE')]:
            down, up = st.columns(2)
            with down:
                modulation_chart(frame, radio, 'dl', label + ' · modulazione download', levels)
            with up:
                modulation_chart(frame, radio, 'ul', label + ' · modulazione upload', levels)
    st.subheader('Tendenze e avvisi')
    st.caption('Confronto descrittivo: mediana degli ultimi 10 minuti rispetto ai 20 precedenti. Non ? una previsione.')
    trends = analyse_radio(frame, expected_interval=expected_interval)
    ready = [item for item in trends if item['delta_db'] is not None]
    if ready:
        labels = {'stable': 'Stabile', 'improving': 'In miglioramento', 'degrading': 'In peggioramento'}
        rows = [{'Metrica': item['label'], 'Andamento': labels[item['state']],
                 'Variazione (dB)': item['delta_db'], 'Minuti di riferimento': item['baseline_bins'],
                 'Minuti recenti': item['recent_bins']} for item in ready]
        st.dataframe(pd.DataFrame(rows), hide_index=True, alt='Tendenze recenti delle metriche radio sullo stesso PCI')
        for item in ready:
            if item['alert']:
                st.warning(f"Calo rilevato su {item['label']}: {abs(item['delta_db']):.1f} dB rispetto al riferimento sullo stesso PCI. Controlla il segnale; questo avviso non identifica la causa.")
    if len(ready) < 4:
        st.info('Per alcune metriche manca un riferimento recente sufficiente. Servono almeno 20 minuti continui sullo stesso PCI, con misure in almeno 5 minuti recenti e 10 minuti precedenti. Cambi di PCI, pause o dati scaduti azzerano il confronto.')
    st.caption('Soglie di variazione: andamento da 3 dB RSRP / 2 dB SINR; avviso da un calo di 6 dB RSRP / 4 dB SINR. Gli avvisi sono ricalcolati dai campioni salvati. Le previsioni richiederanno uno storico più lungo e una verifica su dati futuri.')
    if frame.empty:
        st.info('Nessun campione nel periodo selezionato. Prova “Tutto” per consultare lo storico.')
    else:
        left, right = st.columns(2)
        with left:
            chart(frame, {'nr_rsrp': '5G NR', 'lte_rsrp': 'LTE'}, 'Potenza del segnale', 'dBm')
        with right:
            chart(frame, {'nr_sinr': '5G NR', 'lte_sinr': 'LTE'}, 'Qualità del segnale', 'dB')
        if st.toggle('Mostra lo storico MCS', value=False, key='mcs_history'):
            down, up = st.columns(2)
            with down:
                chart(frame, {'nr_dl_mcs': '5G NR', 'lte_dl_mcs': 'LTE'}, 'MCS download', 'Indice MCS', discrete=True)
            with up:
                chart(frame, {'nr_ul_mcs': '5G NR', 'lte_ul_mcs': 'LTE'}, 'MCS upload', 'Indice MCS', discrete=True)
        display = frame.copy()
        display['ts'] = display['ts'].dt.tz_convert('Europe/Rome').dt.strftime('%d/%m/%Y %H:%M:%S %Z')
        display = display.rename(columns={'ts': 'Data e ora', 'network_type': 'Rete', 'nr_pci': 'PCI 5G',
            'nr_rsrp': 'RSRP 5G (dBm)', 'nr_sinr': 'SINR 5G (dB)', 'lte_pci': 'PCI LTE',
            'lte_rsrp': 'RSRP LTE (dBm)', 'lte_sinr': 'SINR LTE (dB)',
            'nr_dl_mcs': 'MCS 5G download', 'nr_ul_mcs': 'MCS 5G upload',
            'nr_dl_mod': 'Modulazione 5G download', 'nr_ul_mod': 'Modulazione 5G upload',
            'lte_dl_mcs': 'MCS LTE download', 'lte_ul_mcs': 'MCS LTE upload',
            'lte_dl_mod': 'Modulazione LTE download', 'lte_ul_mod': 'Modulazione LTE upload'})
        st.subheader('Campioni recenti')
        st.dataframe(display.iloc[::-1].head(100), hide_index=True, alt='Ultimi cento campioni radio validi')
        st.download_button('Scarica il periodo in CSV', display.to_csv(index=False).encode('utf-8-sig'),
                           file_name='nx200_segnali.csv', mime='text/csv', icon=':material/download:')
        st.caption(f"{len(frame)} campioni nel periodo · massimo {snapshot['limit']} visualizzati ed esportati. I valori zero sono misure valide; i valori mancanti restano vuoti.")
    if snapshot['excluded']:
        st.caption(f"Esclusi {snapshot['excluded']} record storici privi di metriche radio.")
    if not snapshot['errors'].empty:
        st.subheader('Ultimi errori di raccolta')
        errors = snapshot['errors'].copy()
        errors['ts'] = pd.to_datetime(errors['ts'], utc=True, errors='coerce', format='ISO8601').dt.tz_convert('Europe/Rome').dt.strftime('%d/%m/%Y %H:%M:%S %Z')
        st.dataframe(errors.rename(columns={'ts': 'Data e ora', 'message': 'Errore'}), hide_index=True,
                     alt='Ultimi venti errori riportati dal monitor')


live_view()
