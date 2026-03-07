"""
AgentShield — FastAPI Middleware
Adds security to any FastAPI-based agent server at the HTTP layer.

Usage:
    from fastapi import FastAPI
    from agentshield.integrations.fastapi_middleware import add_agentshield

    app = FastAPI()
    add_agentshield(app, config=ShieldConfig(...))

    @app.post("/agent")
    async def run_agent(request: AgentRequest):
        ...  # input already scanned, rate limited before it gets here
"""
from .core import AgentShield, ShieldConfig, SecurityViolation, RateLimitExceeded


def add_agentshield(app, config: ShieldConfig = None):
    """
    Attach AgentShield as middleware to a FastAPI app.
    Automatically extracts user_id from Authorization header or falls back to IP.
    """
    try:
        from fastapi import Request
        from fastapi.responses import JSONResponse
        from starlette.middleware.base import BaseHTTPMiddleware
        import json
    except ImportError:
        raise ImportError("FastAPI is required: pip install fastapi")

    shield = AgentShield(config or ShieldConfig())

    class AgentShieldMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            # Identify the user
            user_id = request.headers.get("X-User-ID") or \
                      request.headers.get("Authorization", "")[:32] or \
                      request.client.host

            try:
                # Rate limit check (before reading body, cheapest gate)
                shield.check_rate_limit(user_id)

                # For POST requests with a body, scan the input
                if request.method == "POST":
                    body_bytes = await request.body()
                    body_str = body_bytes.decode("utf-8", errors="replace")

                    # Try to extract the text field from JSON
                    try:
                        body_json = json.loads(body_str)
                        input_text = body_json.get("input") or body_json.get("message") or body_str
                    except json.JSONDecodeError:
                        input_text = body_str

                    # Scan input
                    shield.check_input(input_text, user_id)

                # Call the actual route
                response = await call_next(request)
                return response

            except RateLimitExceeded as e:
                return JSONResponse(status_code=429, content={
                    "error": "rate_limit_exceeded",
                    "message": str(e),
                    "layer": e.layer
                })
            except SecurityViolation as e:
                return JSONResponse(status_code=400, content={
                    "error": "security_violation",
                    "message": str(e),
                    "layer": e.layer,
                    "severity": e.severity
                })

    app.add_middleware(AgentShieldMiddleware)
    return shield
