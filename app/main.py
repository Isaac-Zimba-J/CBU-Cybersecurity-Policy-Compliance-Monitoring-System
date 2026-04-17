from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.database import Base, engine
from app.routers import auth, users, policies, logs, violations, alerts, reports, dashboard

# Create all database tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="CBU Cybersecurity Compliance Monitoring System",
    description="API for monitoring cybersecurity policy compliance at The Copperbelt University",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — allows Angular frontend and agents on the local network to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # In production, restrict to your Angular app's IP
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all routers
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(policies.router)
app.include_router(logs.router)
app.include_router(violations.router)
app.include_router(alerts.router)
app.include_router(reports.router)
app.include_router(dashboard.router)


@app.get("/", tags=["Health"])
def root():
    return {
        "system": "CBU Cybersecurity Compliance Monitoring System",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok"}
