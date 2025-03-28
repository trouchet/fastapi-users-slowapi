from fastapi.security import OAuth2PasswordBearer
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse

from slowapi import Limiter
from slowapi.util import get_remote_address

from jose import JWTError, jwt, ExpiredSignatureError
from pydantic import BaseModel
import passlib.context

from datetime import datetime, timedelta, timezone
import logging

from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    SECRET_KEY: str = "mysecretkey"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 24 * 60
    REDIS_URI: str = "redis://localhost:6379/0"

    class Config:
        env_file = ".env"

settings = Settings()

# Initialize FastAPI and SlowAPI Limiter
app = FastAPI()

# Dependency to hash passwords
pwd_context = passlib.context.CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2PasswordBearer for simulating authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Function to verify user password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Function to create a JWT token
def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)):
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
    "premium": "6/min"
}

DEFAULT_RATE_LIMIT = "5/min"

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.REDIS_URI,
    default_limits=settings.DEFAULT_RATE_LIMIT 
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Dependency to get the current user
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = decode_access_token(token)
        username = payload.get("sub")  # "sub" is the standard claim for user identification
    except HTTPException:
        logger.warning(f"Failed authentication attempt with invalid token: {token}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    
    user = fake_users_db.get(username)
    if user is None:
        logger.warning(f"Authentication failed. User not found for token: {token}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    return user

# Dependency to get the current user's plan and rate limit (returns a tuple: (Plan, user))
def get_current_plan(user: dict = Depends(get_current_user)):
    plan = user["plan"]
    rate_limit = plan_limits.get(plan, DEFAULT_RATE_LIMIT)
    return Plan(name=plan, rate_limit=rate_limit), user

# Custom function to dynamically compute the rate limit based on the request.
# We give 'request' a default value of None so that if SlowAPI calls it with no arguments, it won't error.
def dynamic_rate_limit(request: Request = None) -> str:
    if request is None:
        return settings.DEFAULT_RATE_LIMIT
    
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return settings.DEFAULT_RATE_LIMIT
    print(auth_header)
    token = auth_header.replace("Bearer ", "")
    print(token)

    # Decode token to get username
    try:
        payload = decode_access_token(token)
        username = payload.get("sub")  # "sub" is typically used for user identification
    except HTTPException:
        return DEFAULT_RATE_LIMIT  # Default to lowest rate if token is invalid
    
    user = fake_users_db.get(username)
    if not user:
        return DEFAULT_RATE_LIMIT

    plan = user.get("plan", "free")
    return plan_limits.get(plan, settings.DEFAULT_RATE_LIMIT)


# Endpoint for login (generates the token)
@app.post("/token")
def login_for_access_token(form_data: LoginRequest):
    user = fake_users_db.get(form_data.username)
    if user is None or not verify_password(form_data.password, user["hashed_password"]):
        logger.warning(f"Failed login attempt for username: {form_data.username}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": form_data.username})
    return {"token_type": "bearer", "access_token": access_token}


# Wrap the dynamic_rate_limit function in a lambda that accepts an optional request.
@limiter.limit(lambda request=None: dynamic_rate_limit(request))
@app.get("/plan-limited-endpoint")
async def plan_limited_endpoint(
    request: Request, 
    plan_and_user: tuple = Depends(get_current_plan)
):
    plan, user = plan_and_user
    logger.info(f"User {user['username']} accessed /plan-limited-endpoint with rate limit {plan.rate_limit}")
    return JSONResponse({
        "user": user['username'],
        "plan": plan.name,
        "rate_limit": plan.rate_limit
    })

# Rate limit status check (remaining quota, etc.)
@app.get("/rate-limit-status")
async def rate_limit_status():
    return {"message": "Check the logs for rate limit info."}

# Additional error handling for HTTP exceptions
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    logger.error(f"HTTP error: {exc.detail}")
    return JSONResponse({"message": f"Error occurred: {exc.detail}"})
