#!/usr/bin/env python3
"""
nx200_monitor_final.py - Approccio ibrido definitivo:
  1. Usa Selenium per il login (gestisce popup e sessione UI)
  2. Estrai JSESSIONID dalla sessione Selenium
  3. Usa socket raw con il cookie estratto per le query GDPR
"""

import sys as _sys, pathlib as _pl; _sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))
from nx200_monitor_v4 import TPLinkGdprClient, RawHttpsClient
import argparse
import logging
import sys
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger()

def selenium_login(host: str, password: str, username: str = "admin") -> dict:
    """Login con Selenium, ritorna i cookie."""
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--ignore-certificate-errors")
    opts.add_argument("--ignore-ssl-errors")
    opts.set_capability("acceptInsecureCerts", True)
    
    driver = webdriver.Chrome(options=opts)
    driver.set_page_load_timeout(60)
    
    try:
        log.info("Avvio browser...")
        driver.get(host)
        time.sleep(5)
        
        try:
            pwd_input = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='password']"))
            )
        except TimeoutException:
            log.info("Gia' loggato, continuo...")
            time.sleep(2)
            cookies = {}
            for c in driver.get_cookies():
                cookies[c["name"]] = c["value"]
            return cookies
        
        pwd_input.send_keys(password)
        time.sleep(0.5)
        
        driver.execute_script(
            "if (window.jQuery) { jQuery('#pc-login-btn').click(); } "
            "else { document.getElementById('pc-login-btn').click(); }"
        )
        
        time.sleep(1)
        try:
            confirm_btn = driver.find_elements(By.ID, "confirm-yes")
            if confirm_btn and confirm_btn[0].is_displayed():
                log.info("Popup rilevato, clicco...")
                driver.execute_script("arguments[0].click();", confirm_btn[0])
                time.sleep(2)
        except:
            pass
        
        log.info("Attendo login...")
        for _ in range(40):
            try:
                ui = driver.find_elements(By.CSS_SELECTOR, "#main, .navi-side")
                if ui and any(e.is_displayed() for e in ui):
                    log.info("Login OK")
                    time.sleep(2)
                    break
            except:
                pass
            time.sleep(0.5)
        
        cookies = {}
        for c in driver.get_cookies():
            cookies[c["name"]] = c["value"]
        log.info("Cookie estratti: %s", list(cookies.keys()))
        return cookies
        
    finally:
        driver.quit()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="https://192.168.1.1")
    parser.add_argument("--password", default="admin")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    
    try:
        # Step 1: Login con Selenium
        log.info("Step 1: Login con Selenium...")
        cookies = selenium_login(args.host, args.password, args.username)
        jsessionid = cookies.get("JSESSIONID")
        if not jsessionid:
            raise RuntimeError("JSESSIONID non trovato nelle cookies")
        log.info("Session cookie acquired")
        
        # Step 2: Crea client socket raw con il cookie
        log.info("Step 2: Connessione socket raw...")
        http = RawHttpsClient(args.host)
        http.cookies["JSESSIONID"] = jsessionid
        
        # Step 3: Try to get RSA keys (questo puo' funzionare ora che abbiamo la sessione)
        log.info("Step 3: Recupero chiavi RSA...")
        status, _hdrs, body = http.post("/cgi/getParm", b"")
        if status != 200:
            log.warning("getParm HTTP %d, provo comunque...", status)
        else:
            log.info("getParm OK")
        
        # Step 4: Prova una query GDPR diretta
        log.info("Step 4: Query GDPR...")
        query_body = "5\r\n[DEV2_LTE_SERVING_CELL_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nPCI\r\nnetworkType\r\n"
        status, _hdrs, resp = http.post("/cgi_gdpr?9", query_body.encode())
        log.info("Response HTTP %d, %d bytes: %r", status, len(resp), resp[:200])
        
    except Exception as e:
        log.error("Errore: %s", e, exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
