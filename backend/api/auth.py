"""
Authentication API router.
Provides endpoints for registration, login, and user profile management.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database.session import get_db
from models.user import User
from schemas.user import UserCreate, UserLogin, UserResponse
from schemas.token import Token
from core.security import get_password_hash, verify_password, create_access_token
from api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user_in: UserCreate, db: Session = Depends(get_db)):
    """
    Registers a new user account.
    Assigns role 'analyst' by default (or 'admin' if this is the first user in DB).
    """
    # Check if username exists
    existing_username = db.query(User).filter(User.username == user_in.username).first()
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username is already registered",
        )

    # Check if email exists
    existing_email = db.query(User).filter(User.email == user_in.email).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already registered",
        )

    # First user automatically gets 'admin' role
    total_users = db.query(User).count()
    assigned_role = "admin" if total_users == 0 else "analyst"

    new_user = User(
        username=user_in.username,
        email=user_in.email.lower(),
        password_hash=get_password_hash(user_in.password),
        role=assigned_role,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post("/login", response_model=Token)
def login(login_in: UserLogin, db: Session = Depends(get_db)):
    """
    Authenticates user with username or email and password. Returns JWT access token.
    """
    input_str = login_in.username_or_email.strip().lower()
    
    # Query by username or email
    user = (
        db.query(User)
        .filter((User.username == input_str) | (User.email == input_str))
        .first()
    )

    if not user or not verify_password(login_in.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account",
        )

    access_token = create_access_token(subject=user.id, role=user.role)
    return Token(access_token=access_token, token_type="bearer")


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """
    Retrieves current authenticated user profile.
    """
    return current_user
