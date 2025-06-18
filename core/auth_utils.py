from datetime import UTC, datetime
from logging import getLogger

import jwt
from clerk_sdk import Clerk, ClerkAPIException
from clerk_sdk.jwt import JWT
from fastapi import Header, HTTPException

from core.config import get_settings
from core.models.auth import AuthContext, EntityType

logger = getLogger(__name__)

__all__ = ["verify_token"]

# Load settings once at import time
settings = get_settings()

# Initialize Clerk SDK
clerk_client = Clerk(secret_key=settings.CLERK_SECRET_KEY)


async def verify_token(authorization: str = Header(None)) -> AuthContext:  # noqa: D401 – FastAPI dependency
    """Return an :class:`AuthContext` for a valid JWT bearer *authorization* header.

    In *dev_mode* we skip cryptographic checks and fabricate a permissive
    context so that local development environments can quickly spin up
    without real tokens.
    """

    # ------------------------------------------------------------------
    # 1. Development shortcut – trust everyone when *dev_mode* is active.
    # ------------------------------------------------------------------
    if settings.dev_mode:
        return AuthContext(
            entity_type=EntityType(settings.dev_entity_type),
            entity_id=settings.dev_entity_id,
            permissions=set(settings.dev_permissions),
            user_id=settings.dev_entity_id,  # In dev mode, entity_id == user_id
            organization_id=None, # No org in dev mode for now
        )

    # ------------------------------------------------------------------
    # 2. Normal token verification flow
    # ------------------------------------------------------------------
    if not authorization:
        logger.info("Missing authorization header")
        raise HTTPException(
            status_code=401,
            detail="Missing authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = authorization[7:]  # Strip "Bearer " prefix

    try:
        # Verify the token using Clerk SDK
        # This automatically checks expiry, signature, etc.
        # We can also pass `issuer` or `audience` if needed for more strict validation
        verified_token_claims = clerk_client.verify_token(token=token)

        user_id = verified_token_claims.get("sub")
        if not user_id:
            logger.error("Clerk token missing 'sub' (user_id) claim.")
            raise HTTPException(status_code=401, detail="Invalid token: Missing user identifier")

        organization_id = verified_token_claims.get("org_id") # This might be specific to your Clerk setup

        # Assuming entity_type is USER when using Clerk.
        # Permissions and app_id might need different handling with Clerk.
        ctx = AuthContext(
            entity_type=EntityType.USER,
            entity_id=user_id, # Clerk's user_id ('sub') maps to entity_id
            user_id=user_id,
            organization_id=organization_id,
            app_id=None, # Or derive from token if available/needed
            permissions={"read", "write"}, # Default permissions for Clerk users
        )
    except ClerkAPIException as exc:
        logger.error(f"Clerk token verification failed: {exc}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc.errors[0].long_message if exc.errors else str(exc)}") from exc
    except Exception as exc: # Catch any other unexpected errors during token processing
        logger.error(f"Unexpected error during token verification: {exc}")
        raise HTTPException(status_code=500, detail="Token processing error")


    # ------------------------------------------------------------------
    # Enterprise enhancement – swap database & vector store based on app_id
    # ------------------------------------------------------------------
    try:
        from core import api as core_api  # type: ignore
        from ee.db_router import (  # noqa: WPS433 – runtime import
            get_database_for_app,
            get_multi_vector_store_for_app,
            get_vector_store_for_app,
        )

        # Replace DB connection pool
        core_api.document_service.db = await get_database_for_app(ctx.app_id)  # noqa: SLF001

        # Replace vector store (if available)
        vstore = await get_vector_store_for_app(ctx.app_id)
        if vstore is not None:
            core_api.vector_store = vstore  # noqa: SLF001 – monkey-patch
            core_api.document_service.vector_store = vstore  # noqa: SLF001 – monkey-patch

        # Route ColPali multi-vector store (if service uses one)
        try:
            mv_store = await get_multi_vector_store_for_app(ctx.app_id)
            if mv_store is not None:
                core_api.document_service.colpali_vector_store = mv_store  # noqa: SLF001 – monkey-patch
        except Exception as mv_exc:  # pragma: no cover – log, but don't block request
            logger.debug("MultiVector store routing skipped: %s", mv_exc)
    except ModuleNotFoundError:
        # Enterprise package not installed – nothing to do.
        pass

    return ctx
