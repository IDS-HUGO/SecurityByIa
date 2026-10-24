# Caso que debe detectar (Control 7): endpoint costoso sin rate limit
from fastapi import FastAPI

app = FastAPI()


@app.post("/api/auth/login")  # ruleid: py-route-without-ratelimit-ctl7
def login(credentials: Credentials):
    return authenticate(credentials)


@app.post("/api/llm/chat")  # ruleid: py-route-without-ratelimit-ctl7
def chat(prompt: Prompt):
    return llm.complete(prompt)


# Caso seguro: rate limiting por IP y usuario con límites por costo del endpoint
from slowapi import Limiter

limiter = Limiter(key_func=lambda request: request.client.host)


@app.post("/api/auth/login-safe")
@limiter.limit("5/minute")
def login_safe(credentials: Credentials):
    return authenticate(credentials)


@app.post("/api/llm/chat-safe")
@limiter.limit("10/minute")
def chat_safe(prompt: Prompt):
    return llm.complete(prompt)
