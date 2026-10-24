# Control 1 (inventario v1.0): CORS minimizado solo orígenes confiables
from fastapi.middleware.cors import CORSMiddleware

# Caso que debe detectar: comodín de orígenes junto a credenciales
app.add_middleware(
    CORSMiddleware(  # ruleid: py-cors-wildcard-credentials-ctl1
        allow_origins=["*"],
        allow_credentials=True,
    )
)

# Caso que debe detectar: métodos y headers comodín sin necesidad
TRUSTED = ["https://app.example.com"]
app.add_middleware(
    CORSMiddleware(  # ruleid: py-cors-wildcard-methods-headers-ctl1
        allow_origins=TRUSTED,
        allow_methods=["*"],
        allow_headers=["*"],
    )
)

# Caso que debe detectar (Django): todos los orígenes permitidos
CORS_ALLOW_ALL_ORIGINS = True  # ruleid: py-django-cors-all-origins-ctl1

# Casos seguros: lista explícita de orígenes confiables, métodos y headers acotados
app.add_middleware(
    CORSMiddleware(
        allow_origins=TRUSTED,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization"],
    )
)
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
