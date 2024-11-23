from datetime import datetime, UTC
from typing import List, Union, Dict, Set
from fastapi import FastAPI, HTTPException, Depends, Header, APIRouter
from fastapi.middleware.cors import CORSMiddleware
import jwt

from core.models.request import IngestRequest, QueryRequest

from .models.documents import (
    Document,
    DocumentResult,
    ChunkResult,
    EntityType
)
from .models.auth import AuthContext
from .services.document_service import DocumentService
from .config import get_settings
from .database import MongoDatabase
from .vector_store import MongoDBAtlasVectorStore
from .storage import S3Storage
from .parser import UnstructuredAPIParser
from .embedding_model import OpenAIEmbeddingModel
from .services.uri_service import get_uri_service


# Initialize FastAPI app
app = FastAPI(title="DataBridge API")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Initialize service
settings = get_settings()

# Initialize components
database = MongoDatabase(
    **settings.get_mongodb_settings()
)

vector_store = MongoDBAtlasVectorStore(
    settings.MONGODB_URI,
    settings.DATABRIDGE_DB,
    "document_chunks",
    "vector_index"
)

storage = S3Storage(
    **settings.get_storage_settings()
)

parser = UnstructuredAPIParser(
    api_key=settings.UNSTRUCTURED_API_KEY,
    chunk_size=settings.CHUNK_SIZE,
    chunk_overlap=settings.CHUNK_OVERLAP
)

embedding_model = OpenAIEmbeddingModel(
    api_key=settings.OPENAI_API_KEY,
    model_name=settings.EMBEDDING_MODEL
)

# Initialize document service
document_service = DocumentService(
    database=database,
    vector_store=vector_store,
    storage=storage,
    parser=parser,
    embedding_model=embedding_model
)


async def verify_token(authorization: str = Header(...)) -> AuthContext:
    """Verify JWT Bearer token."""
    try:
        if not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="Invalid authorization header"
            )
        
        token = authorization[7:]  # Remove "Bearer "
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        
        if datetime.fromtimestamp(payload["exp"], UTC) < datetime.now(UTC):
            raise HTTPException(status_code=401, detail="Token expired")

        return AuthContext(
            entity_type=EntityType(payload["type"]),
            entity_id=payload["entity_id"],
            app_id=payload.get("app_id"),
            permissions=set(payload.get("permissions", ["read"]))
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=str(e))


# API endpoints
@app.post("/documents", response_model=Document)
async def ingest_document(
    request: IngestRequest,
    auth: AuthContext = Depends(verify_token)
) -> Document:
    """Ingest a new document."""
    try:
        return await document_service.ingest_document(request, auth)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/query", response_model=Union[List[ChunkResult], List[DocumentResult]])
async def query_documents(
    request: QueryRequest,
    auth: AuthContext = Depends(verify_token)
):
    """Query documents with specified return type."""
    try:
        return await document_service.query(request, auth)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/documents", response_model=List[Document])
async def list_documents(
    auth: AuthContext = Depends(verify_token),
    skip: int = 0,
    limit: int = 100
):
    """List accessible documents."""
    try:
        return await document_service.db.get_documents(auth, skip, limit)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/documents/{document_id}", response_model=Document)
async def get_document(
    document_id: str,
    auth: AuthContext = Depends(verify_token)
):
    """Get document by ID."""
    try:
        doc = await document_service.db.get_document(document_id, auth)
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")
        return doc
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


auth_router = APIRouter(prefix="/auth", tags=["auth"])


@auth_router.post("/developer-token")
async def create_developer_token(
    dev_id: str,
    app_id: str = None,
    expiry_days: int = 30,
    permissions: Set[str] = None,
    auth: AuthContext = Depends(verify_token)
) -> Dict[str, str]:
    """Create a developer access URI."""
    # Verify requesting user has admin permissions
    if "admin" not in auth.permissions:
        raise HTTPException(
            status_code=403,
            detail="Admin permissions required"
        )

    uri_service = get_uri_service()
    uri = uri_service.create_developer_uri(
        dev_id=dev_id,
        app_id=app_id,
        expiry_days=expiry_days,
        permissions=permissions
    )

    return {"uri": uri}


@auth_router.post("/user-token")
async def create_user_token(
    user_id: str,
    expiry_days: int = 30,
    permissions: Set[str] = None,
    auth: AuthContext = Depends(verify_token)
) -> Dict[str, str]:
    """Create a user access URI."""
    # Verify requesting user has admin permissions
    if "admin" not in auth.permissions:
        raise HTTPException(
            status_code=403,
            detail="Admin permissions required"
        )

    uri_service = get_uri_service()
    uri = uri_service.create_user_uri(
        user_id=user_id,
        expiry_days=expiry_days,
        permissions=permissions
    )

    return {"uri": uri}

# Add to your main FastAPI app
app.include_router(auth_router)
