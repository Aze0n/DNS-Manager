from fastapi import APIRouter, Request, Response, HTTPException
from app.core.security import verify_password, derive_encryption_key

router = APIRouter()

@router.post("/login")
def login(data: dict, response: Response):
    password = data.get("password")
    if not verify_password(password):
        raise HTTPException(status_code=401, detail="invalid password")

    kek, _ = derive_encryption_key(password)
    response.set_cookie("session_id", "valid", httponly=True, secure=True)
    # KEK ggf. serverseitig speichern
    return {"message": "login ok"}

@router.post("/logout")
def logout(response: Response):
    response.delete_cookie("session_id")
    return {"message": "logged out"}

@router.get("/protected_test")
def protected_test(request: Request):
    if request.cookies.get("session_id") != "valid":
        raise HTTPException(status_code=401, detail="not logged in")
    return {"message": "zugriff gewährt"}
