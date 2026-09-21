from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy import create_engine,Integer,String,Boolean,ForeignKey,select,JSON,DateTime,or_,text
from sqlalchemy.orm import sessionmaker,DeclarativeBase,Session,Mapped,mapped_column
from typing import Optional
from dotenv import load_dotenv
import os
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta, date
from fastapi.security import HTTPBearer

bearer_scheme= HTTPBearer()
print (status)
load_dotenv()

DATABASE_URL= os.getenv("DB_URL")
JWT_SECRET= os.getenv("JWT_SECRET")
JWT_EXPIRATION_MINUTES= int(os.getenv("JWT_EXPIRATION_MINUTES"))

engine= create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal= sessionmaker(autocommit= False, autoflush= False, bind= engine)


def get_db():
    db= SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[int]= mapped_column(Integer, primary_key= True, autoincrement= True)
    user_name: Mapped[str]= mapped_column(String, nullable= False)
    email: Mapped[str]= mapped_column(String, unique= True, nullable= False)
    full_name: Mapped[Optional[str]]= mapped_column(String, nullable= True)
    hashed_password: Mapped[str]= mapped_column(String, nullable= False)
    disabled: Mapped[Optional[bool]]= mapped_column(Boolean, default= False)
    role: Mapped[Optional[str]]= mapped_column(String, default= "user")
    created_at: Mapped[datetime]= mapped_column(DateTime, default= datetime.now)
    updated_at: Mapped[datetime]= mapped_column(DateTime, default= datetime.now)
     


class Note(Base):
    __tablename__ = "notes"

    id: Mapped[int]= mapped_column(Integer, primary_key= True, autoincrement= True)
    title: Mapped[str]= mapped_column(String, nullable= False)
    content: Mapped[str]= mapped_column(String, nullable= False)
    owner_username: Mapped[str]= mapped_column(String, ForeignKey("users.user_name"), nullable= False)
    is_public: Mapped[bool]= mapped_column(Boolean, default= False)
    tags: Mapped[Optional[list]]= mapped_column(JSON) 
    created_at: Mapped[datetime]= mapped_column(DateTime, default= datetime.now)
    updated_at: Mapped[datetime]= mapped_column(DateTime, default= datetime.now)


#User.__table__.drop(engine)

Base.metadata.create_all(bind= engine)

password_context= CryptContext(schemes=["bcrypt"], deprecated="auto") 

def seed_admin():
    db= SessionLocal()
    user= User(
        email= "admin@gmail.com",
        full_name= "User Admin",
        user_name= "Admin",
        hashed_password= password_context.hash("admin123"),
        disabled= False,
        role= "admin"
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()

#seed_admin()


# Pydantic validation models
class UserLogin(BaseModel):
    email: EmailStr
    hashed_password: str


class UserCreate(UserLogin):
    user_name: str
    full_name: Optional[str]
    disabled: Optional[bool]= False
    role: Optional[str]= "user"


class UserUpdate(BaseModel):
    email: Optional[EmailStr]
    hashed_password: Optional[str]
    full_name: Optional[str]
    disabled: Optional[bool]= False


class NoteCreate(BaseModel):
    title: str
    content: str
    is_public: bool = False
    tags: Optional[list[str]] = None

class NoteUpdate(BaseModel):
    title: Optional[str]= None
    content: Optional[str] = None
    is_public: Optional[bool]= False
    tags: Optional[list[str]] = None


app = FastAPI()

# Authentication endpoints
# POST /auth/register: Register new user
@app.post("/auth/register", tags= ["Authentication"])
def register_user(payload: UserCreate, db: Session= Depends(get_db)):
    try:
        query= select(User).where(User.email==payload.email)
        existing_user= db.execute(query).scalar_one_or_none()
        if existing_user:
            raise HTTPException(
                status_code = 400,
                detail = "User with this email already exists"
            )
        new_user= User(
            email= payload.email,
            user_name= payload.user_name,
            full_name= payload.full_name,
            hashed_password= password_context.hash(payload.hashed_password),
            disabled= payload.disabled,
            role= payload.role
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return {
            "status_code": 201,
            "success": True,
            "message": "User registered successfully",
            "data": new_user
        }

    except Exception as e:
        raise HTTPException(
            status_code = 500,
            detail = "An error occurred while registering the user"
        )


# POST /auth/token: Login and get JWT token Return access_token and token_type
@app.post("/auth/token", tags= ["Authentication"])
def login_user(payload: UserLogin, db: Session= Depends(get_db)):
    try:
        email= payload.email
        hashed_password= payload.hashed_password
        query= select(User).where(User.email==email)
        user= db.execute(query).scalar_one_or_none()
        if not user:
            raise HTTPException(
                status_code =401,
                detail = "Invalid credenials, try again"
            )
        is_password= password_context.verify(hashed_password, user.hashed_password)
        if not is_password:
            raise HTTPException(
                status_code = 401,
                detail = "Invalid credentials, try again"
            )

        jwt_payload= {
            "user_id": user.user_id,
            "username": user.user_name,
            "role": user.role,
            "exp": datetime.now()+ timedelta(minutes= JWT_EXPIRATION_MINUTES)
        }
        token= jwt.encode(jwt_payload, JWT_SECRET, algorithm= "HS256")
        data= {
            "access_token": token,
            "user": user
        }
        return {
            "status_code": 200,
            "success": True,
            "message": "Login successful",
            "data": data
        }
    except Exception as e:
        raise HTTPException(
            status_code = e.status_code or 500,
            detail = e.detail or "An error occurred while trying to login"
        )

#User Management
#GET /users/me: Get current user info

def verify_token(token: str):
    print("verify_token", token)
        # if not token:
        #     raise HTTPException(
        #         status_code= 401,
        #         detail= "Enter a  valid token and try again"
        #     )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms= ["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code = 401,
            detail = "Session expired, please Login again" 
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code = 401,
            detail = "Invalid token, please Login again"
        ) 
   


def get_current_user(cred= Depends(bearer_scheme)):
    try:
        print(cred)
        token= cred.credentials
        print("token",token)
        result= verify_token(token)
        print(result)
        if not result:
            raise HTTPException(
                status_code = 401,
                detail = "Invalid token, try again"
            )
        return result
    except Exception as e:
        raise HTTPException(
            status_code= e.status_code or 500,
            detail= e.detail or "Internal server error, try again"
        )
    

@app.get("/users/me", tags= ["User Management"])
def get_my_profile(db: Session= Depends(get_db), current_user= Depends(get_current_user)):
    try:
        query= select(User).where(User.user_id==current_user["user_id"])
        user= db.execute(query).scalar_one_or_none()
        return {
            "status_code": 200,
            "success": True,
            "message": "User profile retrieved successfully",
            "data": user
        }
    except Exception as e:
        raise HTTPException(
            status_code= e.status_code or 500,
            detail= e.detail or "An error occurred while retrieving user profile"
        )


# GET /users/: List all users (admin only)

def is_admin(current_user=Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code= 403,
            detail= "Access denied, admin only"
        )

@app.get("/users", tags= ["User Management"])
def get_all_users(db: Session= Depends(get_db), current_user= Depends(is_admin)):
    try:
        query= select(User)
        users= db.execute(query).scalars().all()
        return{
            "status_code": 200,
            "success": True,
            "message": "Users retrieved successfully",
            "data": users
        }
    except Exception as e:
        raise HTTPException(
            status_code= e.status_code or 500,
            detail= e.detail or "Internal server error"
        )


#PUT /users/me: Update current user
@app.put("/users/me", tags= ["User Management"])
def update_my_profile(payload: UserUpdate, db: Session= Depends(get_db), current_user= Depends(get_current_user)):
    try:
        query= select(User).where(User.user_id==current_user["user_id"])
        user= db.execute(query).scalar_one_or_none()
        if not user:
            raise HTTPException(
                status_code= 404,
                detail= "User not found"
            )
        for key, value in payload.model_dump(exclude_unset=True).items():
            if key == "hashed_password":
                setattr(user, key, password_context.hash(value))
            else:
                setattr(user, key, value)
        db.commit()
        db.refresh(user)
        return {
            "status_code": 200,
            "success": True,
            "message": "Profile updated successfully",
            "data": user
        }
    except Exception as e:
        raise HTTPException(
            status_code= e.status_code or 500,
            detail= e.detail or "Internal server error, try again"
        )



# DELETE /users/me: Delete current user
@app.delete("/users/me", tags= ["User Management"])
def delete_my_profile(db: Session= Depends(get_db), current_user= Depends(get_current_user)):
    try:
        query= select(User).where(User.user_id==current_user["user_id"])
        user= db.execute(query).scalar_one_or_none()
        db.delete(user)
        db.commit()
        return {
            "status_code": 200,
            "success": True,
            "message": "User deleted successfully"
        }
    except Exception as e:
        raise HTTPException (
            status_code= e.status_code or 500,
            detail= e.detail or "Delete failed"
        )



# POST /notes/: Create a note (authenticated)
@app.post("/notes", tags= ["Notes"])
def create_note(payload: NoteCreate, db: Session= Depends(get_db), current_user= Depends(get_current_user)):
    try:
        new_note= Note(
            title= payload.title,
            content= payload.content,
            owner_username= current_user["username"],
            is_public= payload.is_public,
            tags= payload.tags
        )
        db.add(new_note)
        db.commit()
        db.refresh(new_note)
        return {
            "status_code": "200",
            "message": "New note added successfully",
            "data": new_note
        }
    except Exception as e:
        raise HTTPException (
            status_code= 500,
            detail= "An error occured while trying to add new note"
        )


# GET /notes/: Get all notes
# For regular users: only their notes or public notes
# For admins: all notes
# Query params: tag, search_term
@app.get("/notes", tags= ["Notes"])
def get_notes(tag: str | None= None,
              search_term: str| None= None,
              db: Session= Depends(get_db), 
              current_user= Depends(get_current_user)):
    try:
        if current_user["role"]== "admin":
            query= select(Note)
        else:
            query= select(Note).where(Note.owner_username==current_user["username"])
        if tag:
            query = query.where(Note.tags.contains(tag)) #.where(text("exists (select 1 from json_each(Note.tags) where json_each.value=: tag_param)")).params(tag_param=tag)
        if search_term:
            query= query.where(
                or_(
                    Note.title.ilike(f"%{search_term}%"),
                    Note.content.ilike(f"%{search_term}%")
                )
            )
        notes= db.execute(query).scalars().all()
        print(notes)
        if not notes:
            raise HTTPException (
                status_code= 404,
                detail= "Note does not exist"
            ) 
        return {
            "status_code": 200,
            "success": True,
            "message": "Notes retrieved successfully",
            "data": notes
        }
    except HTTPException as e:
            print(e)
            raise HTTPException (
                status_code= e.status_code or 500,
                detail= e.detail or "Internal server error"
            )
    except Exception as f:
        print (f)
        raise HTTPException (
                status_code= 500,
                detail= "Internal server error"
            )


# GET /notes/{note_id}: Get a specific note
#Check permissions (owner or admin, or is_public)
@app.get("/notes/{note_id}", tags= ["Notes"])
def get_a_note(id: int, db:Session= Depends(get_db), current_user= Depends(get_current_user)):
    try:
        query= select(Note).where(Note.id==id)
        note= db.execute(query).scalar_one_or_none()

        if not note:
            raise HTTPException (
                status_code= 404,
                detail= "Note not found"
            )

        is_owner= note.owner_username == current_user["username"]
        is_admin= current_user["role"]== "admin"
        is_public= note.is_public == True

        if not (is_owner or is_admin or is_public):
            raise HTTPException(
                status_code= 403,
                detail= "You do not have permission to view this note"
            )
        return{
            "status_code": 200,
            "success": True,
            "message": "Note retrieved successfully",
            "data": note
        }
    except Exception as e:
        raise HTTPException(
            status_code= e.status_code or 500,
            detail= e.detail or "An error occurred while trying to retrieve note"
        )

# PUT /notes/{note_id}: Update a note (owner or admin only)
@app.put("/notes/{note_id}", tags= ["Notes"])
def Update_note(id: int, payload: NoteUpdate, 
                db: Session= Depends(get_db), current_user= Depends(get_current_user)):
    try:
        query= select(Note).where(Note.id==id)
        note= db.execute(query).scalar_one_or_none()

        if not note:
            raise HTTPException(
                status_code= 404,
                detail= "Note not found"
            )
        is_owner= note.owner_username == current_user["username"]
        is_admin= current_user["role"] == "admin"

        if not (is_owner or is_admin):
            raise HTTPException(
                status_code= 403,
                detail= "Unauthorized access"
            )

        for key, value in payload.model_dump(exclude_unset=True).items():
            setattr(note, key, value)
        db.commit()
        db.refresh(note)
        return {
            "status_code": 200,
            "success": True,
            "message": "Note update successful",
            "data": note
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException (
            status_code= 500,
            detail= "Internal server error"
        )


# DELETE /notes/{note_id}: Delete a note (owner or admin only)
@app.delete("/notes/{note_id}", tags= ["Notes"])
def delete_a_note(id: int, db: Session= Depends(get_db), current_user= Depends(get_current_user)):
    try:
        query= select(Note).where(Note.id==id)
        note= db.execute(query).scalar_one_or_none()

        if not note:
            raise HTTPException (
                status_code= 404,
                detail= "Note not found"
            )    
        is_owner= note.owner_username == current_user["username"]
        is_admin= current_user["role"] == "admin"

        if not (is_owner or is_admin):
            raise HTTPException(
                status_code= 403,
                detail= "You do not have permission to delete this note"
            )

        db.delete(note)
        db.commit()
        return {
            "status_code": 200,
            "success": True,
            "message": "Note deleted successfully"
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException (
            status_code= 500,
            detail= "Delete failed, an internal server error occurred"
        )



# import sqlite3
# conn= sqlite3.connect("personal_notes.db")
# curr= conn.cursor()
# curr.execute("drop table note")
# curr.execute("select * from note").fetchall()