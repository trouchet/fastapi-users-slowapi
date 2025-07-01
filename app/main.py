from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi import Limiter

from jose import JWTError, jwt, ExpiredSignatureError
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import BaseModel
import passlib.context
from redis import Redis, ConnectionPool

from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from functools import wraps
import logging

class Settings(BaseSettings):
    SECRET_KEY: str = "mysecretkey"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: timedelta = timedelta(minutes=24 * 60)
    CLEANUP_INTERVAL_MINUTES: int = 10
    DEFAULT_RATE_LIMIT: str = "5/minute"
    TOKEN_TTL: int = 60 * 60
    REDIS_URI: str = "redis://redis:6379/0"

    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()

def start_scheduler():
    scheduler = BackgroundScheduler()
    # Trigger to run the task every minute (adjust interval as necessary)
    scheduler.add_job(
        cleanup_revoked_tokens, 
        IntervalTrigger(minutes=settings.CLEANUP_INTERVAL_MINUTES), 
        id='cleanup_revoked_tokens', 
        name='Clean up revoked tokens every minute', 
        replace_existing=True
    )
    scheduler.start()

@asynccontextmanager
async def lifespan(app_: FastAPI):
    start_scheduler()
    yield

# Initialize FastAPI and SlowAPI Limiter
app = FastAPI(
    docs_url="/docs",
    openapi_url="/openapi.json",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Inicializa Redis
pool = ConnectionPool.from_url(settings.REDIS_URI)
redis_client = Redis(connection_pool=pool)

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.REDIS_URI,
    default_limits=settings.DEFAULT_RATE_LIMIT 
)
app.state.limiter = limiter 

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Additional error handling for HTTP exceptions
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    logger.error(f"HTTP error: {exc.detail}")
    return JSONResponse({"message": f"Error occurred: {exc.detail}"})

@app.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    # Define the retry time (e.g., 60 seconds from now)
    retry_after_time = datetime.now() + timedelta(seconds=60)
    
    # Format retry time as an HTTP date
    retry_after_http_date = retry_after_time.strftime('%a, %d %b %Y %H:%M:%S GMT')
    
    # Return a JSON response with the Retry-After header
    return JSONResponse(
        status_code=429,
        content={"error": f"Too many requests. Please try again later after {retry_after_http_date} UTC."},
        headers={"Retry-After": retry_after_http_date}
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail}
    )

# Dependency to hash passwords
pwd_context = passlib.context.CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2PasswordBearer for simulating authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Function to verify user password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Function to revoke a token
def cleanup_revoked_tokens():
    expired_keys = redis_client.keys("revoked_token:*")
    for key in expired_keys:
        redis_client.delete(key)

# Function to create a JWT token
def create_access_token(
    data: dict, 
    expires_delta: timedelta = settings.ACCESS_TOKEN_EXPIRE_MINUTES 
):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire.timestamp()})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

# Function to decode a JWT token
def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except ExpiredSignatureError:
        logger.warning("Expired token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except JWTError as e:
        logger.error(f"JWT Error: {e}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def validate_plan(allowed_plans):
    """
    Decorator to restrict access based on user plan.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(
            request: Request, 
            plan_and_user: tuple = Depends(get_current_plan), 
            *args, 
            **kwargs
        ):
            plan, user = plan_and_user

            if plan.name not in allowed_plans:
                logger.warning(f"Unauthorized access attempt by {user['username']} with plan {plan.name}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Your plan '{plan.name}' does not allow access to this resource."
                )

            return await func(request, plan_and_user, *args, **kwargs)

        return wrapper
    return decorator

# Models
class User(BaseModel):
    username: str
    plan: str  # Could be 'free', 'premium', etc.

class Plan(BaseModel):
    name: str
    rate_limit: str  # e.g., '10/min', '100/min'

# Model for login request
class LoginRequest(BaseModel):
    username: str
    password: str

# Fake users database with hashed passwords
fake_users_db = {
    "john_doe": {
        "username": "john_doe", 
        "hashed_password": pwd_context.hash("password123"), 
        "plan": "premium"
    },
    "jane_doe": {
        "username": "jane_doe", 
        "hashed_password": pwd_context.hash("password456"), 
        "plan": "free"
    }
}

# Define rate limits based on the plan
plan_limits = {
    "free": "5/min",
    "premium": "6/min",
    "admin": "9999/min"
}

def is_token_revoked(token: str) -> bool:
    revoked = redis_client.get(f"revoked_token:{token}")
    
    # Explicitly check if the value is None or an empty string
    return bool(revoked)

def revoke_token(token: str):
    """
    Revoke a token with individual TTL by storing each token with its own expiration.
    """
    # Set the token with its own TTL
    redis_client.setex(f"revoked_token:{token}", settings.TOKEN_TTL, 1)


# Function to decode the token and check for revocation
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        
        # Check if the token is revoked
        if is_token_revoked(token):
            logger.warning("Attempted access with a revoked token.")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")
        
        # Proceed with decoding and further checks...
        payload = decode_access_token(token)
        username = payload.get("sub")
        
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
        
    except ExpiredSignatureError:
        logger.error("Token has expired.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except JWTError as e:
        logger.error(f"JWT decoding error: {e}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    
    # Further logic to retrieve and return the user
    user = fake_users_db.get(username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    
    return user

# Dependency to get the current user's plan and rate limit (returns a tuple: (Plan, user))
def get_current_plan(user: dict = Depends(get_current_user)):
    plan = user["plan"]
    rate_limit = plan_limits.get(plan, settings.DEFAULT_RATE_LIMIT)
    return Plan(name=plan, rate_limit=rate_limit), user

# Common function to validate the user and retrieve username
def get_username_from_token(token: str):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        username = payload.get("sub")
        if not username or username not in fake_users_db:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# Function to get user by username
# NOTE: This is usually retrieved by a repository pattern
def get_user_from_username(username: str):
    return fake_users_db.get(username)

# Custom function to dynamically compute the rate limit based on the request.
# We give 'request' a default value of None so that if SlowAPI calls it with no arguments, it won't error.
def dynamic_rate_limit(request: Request = None) -> str:
    if request is None:
        return settings.DEFAULT_RATE_LIMIT
    
    auth_header = request.headers.get("Authorization")
    
    if not auth_header:
        return settings.DEFAULT_RATE_LIMIT
    token = auth_header.replace("Bearer ", "")

    # Decode token to get username
    try:
        payload = decode_access_token(token)
        username = payload.get("sub")  # "sub" is typically used for user identification
    except HTTPException:
        return settings.DEFAULT_RATE_LIMIT  # Default to lowest rate if token is invalid
    
    user = fake_users_db.get(username)
    if not user:
        return settings.DEFAULT_RATE_LIMIT

    plan = user.get("plan", "free")
    return plan_limits.get(plan, settings.DEFAULT_RATE_LIMIT)

# Simplified login endpoint
@app.post("/token")
async def login_for_access_token(form_data: LoginRequest):
    user = get_user_from_username(form_data.username)
    if user is None or not verify_password(form_data.password, user["hashed_password"]):
        logger.warning(f"Failed login attempt for username: {form_data.username}")
        logger.debug("Raising HTTP 401 Unauthorized")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


    access_token = create_access_token(data={"sub": form_data.username})
    return {"token_type": "bearer", "access_token": access_token}

# Simplified refresh token endpoint
@app.post("/refresh")
async def refresh_token(refresh_token: str):
    username = get_username_from_token(refresh_token)
    new_access_token = create_access_token({"sub": username})
    return {"token_type": "bearer", "access_token": new_access_token}

@app.post("/logout")
@limiter.limit(dynamic_rate_limit)
async def logout(
    request: Request, 
    token: str = Depends(oauth2_scheme)
):
    """ Revoke the token, effectively logging out the user. """
    revoke_token(token)
    return {"message": "Successfully logged out"}

# Example of revoking a token
@app.post("/revoke")
async def revoke_token_endpoint(token: str):
    """
    Revoke a token by adding it to Redis with a TTL
    """
    revoke_token(token)
    return {"message": f"Token {token} revoked successfully"}

# Example of checking if a token is revoked
@app.get("/is_token_revoked")
async def is_token_revoked_endpoint(token: str):
    """
    Check if a token is revoked.
    """
    is_revoked = redis_client.exists(f"revoked_token:{token}") > 0
    return {"revoked": is_revoked}

# Example of testing cleanup (can be removed in production)
@app.get("/test_cleanup")
async def test_cleanup():
    cleanup_revoked_tokens()
    return {"message": "Cleanup initiated."}

# Wrap the dynamic_rate_limit function in a lambda that accepts an optional request.
@app.get("/plan-limited-endpoint")
@limiter.limit(dynamic_rate_limit)
async def plan_limited_endpoint(
    request: Request, 
    plan_and_user: tuple = Depends(get_current_plan)
):
    plan, user = plan_and_user
    logger.info(
        f"User {user['username']} accessed /plan-limited-endpoint with rate limit {plan.rate_limit}"
    )
    return JSONResponse({
        "user": user['username'],
        "plan": plan.name,
        "rate_limit": plan.rate_limit
    })

# Endpoint for premium-only content
@app.get("/premium-only-endpoint")
@limiter.limit(dynamic_rate_limit)
@validate_plan(["premium", "admin"])
async def premium_only_endpoint(
    request: Request, 
    plan_and_user: tuple = Depends(get_current_plan)
):
    plan, user = plan_and_user
    return JSONResponse({
        "message": "Welcome to the premium-only endpoint!",
        "user": user['username'],
        "plan": plan.name
    })

@app.get("/users/me")
@limiter.limit(dynamic_rate_limit)
async def read_users_me(
    request: Request, 
    current_user: dict = Depends(get_current_user)
):
    """ Return the current user's information. """
    return {"username": current_user["username"], "plan": current_user["plan"]}

# Rate limit status check (remaining quota, etc.)
@app.get("/rate-limit-status")
@limiter.limit(dynamic_rate_limit)
async def rate_limit_status(request: Request):
    return {"message": "Check the logs for rate limit info."}

@app.get("/health")
async def health():
    return {"status": "ok"}
