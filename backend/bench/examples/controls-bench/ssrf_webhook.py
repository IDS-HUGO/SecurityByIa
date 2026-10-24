import requests


def notificar(user_url, payload):
    requests.post(user_url, json=payload)
    requests.post("https://hooks.example.com/fixed", json=payload)
