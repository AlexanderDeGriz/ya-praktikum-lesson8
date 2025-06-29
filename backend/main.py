from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from typing import List, Dict, Any, Optional
import os
import httpx
import json
from fastapi.middleware.cors import CORSMiddleware
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Можно указать конкретные адреса
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Настройки Keycloak
# раньше был ключ KEYCLOAK_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtEL5kZzj6OX9WCx4AsXHiGsBzx3VvST3t1B7GN7EByW7VO+Fv1LDnZ5D1KX5aRL2RBR1xTY/XS3Az7UhWAmtnHZ2YcUMBWue5+3PJqF+Z82dqiNfCk7Wiqr52+qMlrj4IIoWgnD0Kka8UV3tmGPqtcpJsDjQfiD3a9IYpkGNl3RJE2f0VXqrigV2G+WYuFN8/hyFhhxewEiPO09NYjHFcmtyX6i2geP3yQhC6LMapGaK1OT89YF4VLBr4nHLAd5GIFcXbi2NUNCW9zu5eYZrKr4DgiDwgmNNn8u+tL11U8P1X7vmRMPbyuFh551svGkTj9H9gVrD7yDWd0M4j50dpwIDAQAB"
# KEYCLOAK_ISSUER = "http://localhost:8080/realms/reports-realm"  # или ваш адрес

KEYCLOAK_BASE_URL = "http://keycloak:8080"  # Используем имя сервиса в Docker-сети -- ранее "http://localhost:8080"
KEYCLOAK_BASE_URL_FOR_DECODE = "http://localhost:8080"
KEYCLOAK_REALM = "reports-realm"
KEYCLOAK_ISSUER = f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}"
KEYCLOAK_ISSUER_FOR_DECODE = f"{KEYCLOAK_BASE_URL_FOR_DECODE}/realms/{KEYCLOAK_REALM}"
ALGORITHM = "RS256"
REQUIRED_ROLE = "prothetic_user"

security = HTTPBearer()

# Кэш для хранения публичных ключей
_public_keys_cache = None
_public_keys_cache_time = 0
CACHE_DURATION = 3600  # 1 час

async def get_keycloak_public_keys() -> Dict[str, Any]:
    """
    Получает публичные ключи из Keycloak через OpenID Connect discovery
    """
    global _public_keys_cache, _public_keys_cache_time
    
    import time
    current_time = time.time()
    
    # Проверяем кэш
    if _public_keys_cache and (current_time - _public_keys_cache_time) < CACHE_DURATION:
        logger.info("Using cached public keys")
        return _public_keys_cache
    
    try:
        logger.info(f"Fetching public keys from Keycloak: {KEYCLOAK_ISSUER}")
        async with httpx.AsyncClient() as client:
            # Получаем OpenID Connect discovery document
            discovery_url = f"{KEYCLOAK_ISSUER}/.well-known/openid-configuration"
            logger.info(f"Requesting discovery document: {discovery_url}")
            
            response = await client.get(discovery_url)
            response.raise_for_status()
            
            discovery_data = response.json()
            logger.info("Discovery document received successfully")
            
            jwks_url = discovery_data.get("jwks_uri")
            logger.info(f"JWKS URI: {jwks_url}")
            
            if not jwks_url:
                raise HTTPException(status_code=500, detail="JWKS URI not found in discovery document")
            
            # Получаем JWKS (JSON Web Key Set)
            logger.info(f"Requesting JWKS: {jwks_url}")
            jwks_response = await client.get(jwks_url)
            jwks_response.raise_for_status()
            
            jwks_data = jwks_response.json()
            logger.info(f"JWKS received successfully, keys count: {len(jwks_data.get('keys', []))}")
            
            # Обновляем кэш
            _public_keys_cache = jwks_data
            _public_keys_cache_time = current_time
            
            return jwks_data
            
    except httpx.RequestError as e:
        logger.error(f"Request error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to connect to Keycloak: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get public keys: {str(e)}")

async def decode_jwt(token: str):
    """
    Декодирует JWT токен, получая публичный ключ из Keycloak
    """
    try:
        # Получаем JWKS из Keycloak
        jwks_data = await get_keycloak_public_keys()
        
        # Декодируем токен с использованием JWKS
        payload = jwt.decode(
            token,
            jwks_data,
            algorithms=[ALGORITHM],
            audience=None,  # Можно добавить clientId, если требуется
            issuer=KEYCLOAK_ISSUER_FOR_DECODE
        )
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

async def check_role(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = await decode_jwt(token)
    roles: List[str] = payload.get("realm_access", {}).get("roles", [])
    if REQUIRED_ROLE not in roles:
        raise HTTPException(status_code=403, detail="Insufficient role")
    return payload

@app.get("/reports")
async def get_reports(user=Depends(check_role)):
    return {"message": "Access granted to prothetic_user", "user": user} 