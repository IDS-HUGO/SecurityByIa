from fastapi import FastAPI

app = FastAPI()


@app.post("/api/auth/login")
def login(credentials):
    return authenticate(credentials)


@app.post("/api/llm/chat")
def chat(prompt):
    return llm.complete(prompt)


from slowapi import Limiter

limiter = Limiter(key_func=lambda request: request.client.host)


@app.post("/api/auth/login-safe")
@limiter.limit("5/minute")
def login_safe(credentials):
    return authenticate(credentials)
