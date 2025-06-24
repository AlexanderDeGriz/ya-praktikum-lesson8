from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from typing import List
import os
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Можно указать конкретные адреса
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Настройки (замените на свои значения из Keycloak)
KEYCLOAK_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtEL5kZzj6OX9WCx4AsXHiGsBzx3VvST3t1B7GN7EByW7VO+Fv1LDnZ5D1KX5aRL2RBR1xTY/XS3Az7UhWAmtnHZ2YcUMBWue5+3PJqF+Z82dqiNfCk7Wiqr52+qMlrj4IIoWgnD0Kka8UV3tmGPqtcpJsDjQfiD3a9IYpkGNl3RJE2f0VXqrigV2G+WYuFN8/hyFhhxewEiPO09NYjHFcmtyX6i2geP3yQhC6LMapGaK1OT89YF4VLBr4nHLAd5GIFcXbi2NUNCW9zu5eYZrKr4DgiDwgmNNn8u+tL11U8P1X7vmRMPbyuFh551svGkTj9H9gVrD7yDWd0M4j50dpwIDAQAB"
KEYCLOAK_ISSUER = "http://localhost:8080/realms/reports-realm"  # или ваш адрес
ALGORITHM = "RS256"
REQUIRED_ROLE = "prothetic_user"

security = HTTPBearer()

def get_public_key():
    # Обрезаем -----BEGIN PUBLIC KEY----- и -----END PUBLIC KEY-----
    return f"-----BEGIN PUBLIC KEY-----\n{KEYCLOAK_PUBLIC_KEY}\n-----END PUBLIC KEY-----"

def decode_jwt(token: str):
    try:
        payload = jwt.decode(
            token,
            get_public_key(),
            algorithms=[ALGORITHM],
            audience=None,  # Можно добавить clientId, если требуется
            issuer=KEYCLOAK_ISSUER
        )
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

def check_role(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_jwt(token)
    roles: List[str] = payload.get("realm_access", {}).get("roles", [])
    if REQUIRED_ROLE not in roles:
        raise HTTPException(status_code=403, detail="Insufficient role")
    return payload

@app.get("/reports")
def get_reports(user=Depends(check_role)):
    return {"message": "Access granted to prothetic_user", "user": user} 