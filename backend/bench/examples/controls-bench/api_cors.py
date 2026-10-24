from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware(
        allow_origins=["*"],
        allow_credentials=True,
    )
)

# Caso seguro: lista explícita de orígenes confiables
TRUSTED = ["https://app.example.com"]
app.add_middleware(
    CORSMiddleware(
        allow_origins=TRUSTED,
        allow_credentials=True,
    )
)
