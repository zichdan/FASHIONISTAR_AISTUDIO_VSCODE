# apps/authentication/types/auth_schemas.py

from pydantic import BaseModel, EmailStr, validator
import logging

logger = logging.getLogger('application')

class GoogleAuthSchema(BaseModel):
    """
    Schema for Google authentication input.
    """
    id_token: str

    @validator('id_token')
    def validate_token(cls, v):
        try:
            if not v or len(v) < 50:
                raise ValueError("Invalid Google ID Token")
            return v
        except Exception as e:
            logger.error(f"Validation error for GoogleAuthSchema: {str(e)}")
            raise

class LoginSchema(BaseModel):
    """
    Schema for login input.
    """
    email_or_phone: str
    password: str

class PasswordResetRequestSchema(BaseModel):
    """
    Schema for password reset request.
    """
    email_or_phone: str

class PasswordResetConfirmSchema(BaseModel):
    """
    Schema for password reset confirmation.
    """
    uidb64: str
    token: str
    new_password: str