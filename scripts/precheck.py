#!/usr/bin/env python3
import asyncio
import os
import sys
import logging
from dotenv import load_dotenv

# Load config
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

async def check_redis():
    logger.info("Checking Redis...")
    import redis.asyncio as redis_async
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6380")
    try:
        r = redis_async.from_url(redis_url)
        await r.ping()
        logger.info("✓ Redis is reachable")
        await r.close()
    except Exception as e:
        logger.error(f"✗ Redis check failed: {e}")
        return False
    return True

async def check_opa():
    logger.info("Checking OPA...")
    import httpx
    opa_url = os.getenv("OPA_URL", "http://localhost:8182")
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{opa_url}/health")
            if resp.status_code == 200:
                logger.info("✓ OPA is reachable")
            else:
                logger.warning(f"⚠ OPA returned status {resp.status_code}")
    except Exception as e:
        logger.error(f"✗ OPA check failed: {e}")
        return False
    return True

def check_env():
    logger.info("Checking Environment Variables...")
    required = ["REDIS_URL", "OPA_URL", "JWT_SECRET_KEY"]
    passed = True
    for req in required:
        if not os.getenv(req):
            logger.error(f"✗ Missing required env var: {req}")
            passed = False
        else:
            logger.info(f"✓ {req} is set")
    return passed

def check_certs():
    logger.info("Checking Certificates...")
    cert_dir = os.getenv("CERT_DIR", "./certs")
    if not os.path.exists(cert_dir):
        logger.error(f"✗ Certificate directory not found: {cert_dir}")
        return False
    logger.info("✓ Certificate directory exists")
    return True

def check_spacy():
    logger.info("Checking spaCy Model (en_core_web_lg)...")
    try:
        import spacy
        # Just checking if the module loads. We can check if model exists:
        if spacy.util.is_package("en_core_web_lg"):
            logger.info("✓ spaCy model en_core_web_lg is installed")
            return True
        else:
            logger.error("✗ spaCy model en_core_web_lg is not installed")
            return False
    except ImportError:
        logger.error("✗ spaCy is not installed")
        return False

async def main():
    logger.info("=== Starting Precheck ===")
    results = await asyncio.gather(
        check_redis(),
        check_opa(),
    )
    env_ok = check_env()
    cert_ok = check_certs()
    spacy_ok = check_spacy()
    
    if all(results) and env_ok and cert_ok and spacy_ok:
        logger.info("=== Precheck PASSED ===")
        sys.exit(0)
    else:
        logger.error("=== Precheck FAILED ===")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
