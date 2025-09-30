from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.db_tables_models import UserSession, UserAppProfile
from datetime import datetime

async def get_current_user_from_session(
    request: Request,
    db: Session = Depends(get_db)
):
    session_token = request.cookies.get("session_token")
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing session token.")

    session = db.query(UserSession).filter(
        UserSession.session_token == session_token,
        UserSession.is_active == True,
        UserSession.expires_at > datetime.utcnow()
    ).first()
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session.")

    user = db.query(UserAppProfile).filter_by(cognito_user_id=session.cognito_user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive.")

    # Optionally, update last_accessed
    session.last_accessed = datetime.utcnow()
    db.commit()

    return user
