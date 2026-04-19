"""
AI Shield Intelligence - FastAPI Backend
Main application entry point
"""
import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from logging_config import setup_logging, get_logger, log_with_context

# Configure structured logging
setup_logging(
    log_level=settings.log_level,
    json_format=settings.environment == "production"
)

logger = get_logger(__name__)


async def check_and_trigger_catchup() -> None:
    """
    Check for overdue collections and trigger catch-up if needed.
    
    This function:
    1. Connects to Redis using CollectionStateManager
    2. Retrieves collection:last_run timestamp
    3. Calculates elapsed time since last run
    4. If elapsed > 12 hours: logs overdue detection, queues scheduled_source_fetch task, updates collection:last_run
    5. Handles Redis connection errors gracefully (logs warning, continues startup)
    
    Requirements: 1.1, 1.2, 1.3, 1.4, 2.1, 2.2, 2.3
    """
    from datetime import datetime
    from services.collection_state import get_collection_state_manager
    from tasks import scheduled_source_fetch
    
    logger.info("Checking for overdue collections")
    
    try:
        # Get collection state manager
        state_manager = get_collection_state_manager()
        
        # Check if collection is overdue (>12 hours)
        is_overdue = await state_manager.is_overdue(threshold_hours=12)
        
        if is_overdue:
            # Get last run timestamp for logging
            last_run = await state_manager.get_last_run()
            
            if last_run:
                elapsed = datetime.utcnow() - last_run
                elapsed_hours = elapsed.total_seconds() / 3600
                log_with_context(
                    logger, "warning", "Overdue collection detected",
                    last_run=last_run.isoformat(),
                    elapsed_hours=round(elapsed_hours, 2)
                )
            else:
                logger.warning("No previous collection found, triggering initial collection")
            
            # Queue catch-up collection task
            try:
                task = scheduled_source_fetch.delay()
                logger.info(f"Queued catch-up collection task: {task.id}")
                
                # Update last_run timestamp to prevent duplicate catch-ups
                await state_manager.set_last_run(datetime.utcnow())
                logger.info("Updated collection:last_run timestamp")
                
            except Exception as e:
                logger.error(f"Failed to queue catch-up collection task: {e}", exc_info=True)
        else:
            logger.info("Collection is not overdue, no catch-up needed")
    
    except Exception as e:
        # Handle Redis connection errors gracefully
        logger.warning(f"Failed to check for overdue collections: {e}")
        logger.warning("Continuing startup without catch-up check")
        # Don't raise - allow startup to continue


async def recover_orphaned_analyses() -> int:
    """
    Find threats stuck in 'pending' LLM analysis status with no queued task
    and re-queue them for analysis.
    
    Threats can become orphaned when:
    - Worker restarts drop in-flight enrichment tasks
    - Event loop errors prevent task chaining
    - Enrichment succeeds but analyze_with_llm.delay() fails
    
    Only re-queues threats that have been pending for more than 10 minutes
    (to avoid re-queuing threats that are actively being processed).
    
    Returns:
        Number of threats re-queued
    """
    from datetime import datetime, timedelta
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import select
    from models.threat import Threat
    from tasks import analyze_with_llm
    
    logger.info("Checking for orphaned pending LLM analyses")
    
    try:
        engine = create_async_engine(settings.database_url, echo=False)
        async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        
        async with async_session() as session:
            # Find threats pending for more than 10 minutes (not freshly queued)
            cutoff = datetime.utcnow() - timedelta(minutes=10)
            result = await session.execute(
                select(Threat.id).where(
                    Threat.llm_analysis_status == 'pending',
                    Threat.ingested_at < cutoff
                )
            )
            pending_ids = [str(row[0]) for row in result.all()]
        
        await engine.dispose()
        
        if not pending_ids:
            logger.info("No orphaned pending analyses found")
            return 0
        
        logger.warning(f"Found {len(pending_ids)} orphaned pending analyses, re-queuing")
        
        queued = 0
        for threat_id in pending_ids:
            try:
                analyze_with_llm.delay(threat_id)
                queued += 1
            except Exception as e:
                logger.error(f"Failed to queue orphaned threat {threat_id}: {e}")
        
        logger.info(f"Re-queued {queued} orphaned analyses")
        return queued
    
    except Exception as e:
        logger.warning(f"Failed to recover orphaned analyses: {e}")
        return 0


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """
    Application lifespan manager for startup and shutdown events.
    """
    # Startup
    logger.info("Starting AI Shield Intelligence API")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Database URL: {settings.database_url.split('@')[1] if '@' in settings.database_url else 'configured'}")
    logger.info(f"Redis URL: {settings.redis_url}")
    logger.info(f"MinIO Endpoint: {settings.minio_endpoint}")
    logger.info(f"Ollama URL: {settings.ollama_url}")
    
    # Initialize source manager and start file watcher
    from services.source_manager import get_source_manager
    source_manager = get_source_manager()
    source_manager.start_watching()
    logger.info("Source configuration file watcher started")
    
    # Check for overdue collections and trigger catch-up if needed
    await check_and_trigger_catchup()
    
    # Recover any orphaned pending LLM analyses
    await recover_orphaned_analyses()
    
    yield
    
    # Shutdown
    logger.info("Shutting down AI Shield Intelligence API")
    source_manager.stop_watching()
    logger.info("Source configuration file watcher stopped")


# Create FastAPI application
app = FastAPI(
    title="AI Shield Intelligence API",
    description="Threat intelligence platform for AI/ML security threats",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all HTTP requests with timing and status"""
    start_time = time.time()
    
    # Log request
    log_with_context(
        logger, "info", "HTTP Request",
        method=request.method,
        path=request.url.path,
        client_host=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "unknown")
    )
    
    # Process request
    response = await call_next(request)
    
    # Calculate duration
    duration_ms = (time.time() - start_time) * 1000
    
    # Log response
    log_with_context(
        logger, "info", "HTTP Response",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=round(duration_ms, 2)
    )
    
    return response


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint - API information"""
    return {
        "name": "AI Shield Intelligence API",
        "version": "0.1.0",
        "status": "running",
        "docs": "/docs",
        "health": "/api/v1/health"
    }


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle uncaught exceptions with detailed logging"""
    log_with_context(
        logger, "error", "Unhandled exception",
        method=request.method,
        path=request.url.path,
        exception_type=type(exc).__name__,
        exception_message=str(exc),
        client_host=request.client.host if request.client else None
    )
    logger.error(f"Exception details: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if settings.environment == "development" else "An error occurred"
        }
    )


# Import and include routers
from api import health, sources, search, threats, auth, system, analytics

app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(system.router)
app.include_router(auth.router)
app.include_router(threats.router)
app.include_router(sources.router)
app.include_router(search.router, tags=["search"])
app.include_router(analytics.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.environment == "development"
    )
