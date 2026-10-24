# Casos que deben detectar (C4): URL controlada por el usuario
import requests
import httpx
import urllib.request


def call_webhook(user_url: str):
    requests.post(user_url, json=payload)  # ruleid: py-requests-variable-url-ctl4
    requests.get(  # ruleid: py-requests-fstring-url-ctl4
        f"https://{user_host}/path")
    httpx.get(external_url)  # ruleid: py-requests-variable-url-ctl4
    urllib.request.urlopen(target_url)  # ruleid: py-requests-variable-url-ctl4


# Casos seguros: destino fijo o allowlist cerrada
ALLOWED_HOSTS = {"api.partner.example.com"}
requests.get("https://api.partner.example.com/v1/ping")
requests.post("https://hooks.example.com/fixed", json=payload)
