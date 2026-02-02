# main.py
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import Response
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from app.api.users import router as users_router
from app.api.virtual_machines import router as vm_router
import logging
import time

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Prometheus Metrics
REQUEST_COUNT = Counter(
    "http_requests_total", "Total HTTP Requests", ["method", "endpoint"]
)
REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds", "HTTP request latency", ["endpoint"]
)

# FastAPI App
app = FastAPI()

origins = [
    "http://223.194.20.119:25120", # WAN FE
    "http://10.5.15.3:25120", # LAN FE
    "http://100.101.247.128:25120", # VPN FE
    "http://100.89.35.48:5173", # TEST FE
    "https://k-net.kr",
    "https://doddle.kr"
]

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def metrics_and_cors_middleware(request: Request, call_next):
    start_time = time.time()

    logging.debug(f"Request origin: {request.headers.get('origin')}")
    response = await call_next(request)

    origin = request.headers.get('origin')
    if origin in origins:
        response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    logging.debug(f"Response headers: {response.headers}")

    # Prometheus metrics 기록
    process_time = time.time() - start_time
    REQUEST_COUNT.labels(request.method, request.url.path).inc()
    REQUEST_LATENCY.labels(request.url.path).observe(process_time)

    return response

# Prometheus metrics endpoint
@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

# API Routers
app.include_router(users_router, prefix="/api/users", tags=["users"])
app.include_router(vm_router, prefix="/api/vm", tags=["vm"])
