import os
from contextlib import asynccontextmanager
from datetime import UTC
from typing import Optional

import aiomysql
from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from starlette.staticfiles import StaticFiles

# ================== Конфигурация ==================
SECRET_KEY = "304f1388f317fe2e917a1df468144def7f60586ba96dc80b07d26c68cae00fab"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 604800

MYSQL_HOST = "localhost"
MYSQL_USER = "root"
MYSQL_PASSWORD = "12345678"
MYSQL_DB = "grade_book"
MYSQL_PORT = 3306

PROFILE_PHOTOS_DIR = "profile_photos"
os.makedirs(PROFILE_PHOTOS_DIR, exist_ok=True)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ================== Модели ==================

class User(BaseModel):
    username: str

class UserCreate(User):
    password: str

class UserInDB(User):
    id: int  # добавь это
    hashed_password: str
    role: str = "student"

class Token(BaseModel):
    access_token: str
    token_type: str

class Grade(BaseModel):
    student_id: int
    subject: str
    value: int
    date: str
    teacher_id: int

class Homework(BaseModel):
    class_id: int
    subject: str
    due_date: str
    description: str
    teacher_id: int

class Subject(BaseModel):
    name: str

class Profile(BaseModel):
    user_id: int
    full_name: str
    bio: str
    photo_url: Optional[str] = None


class ClassItem(BaseModel):
    name: str
    student_count: int



class ProfileUpdateRequest(BaseModel):
    full_name: str
    work_place: str
    location: str
    bio: str

# ================== JWT ==================

import json
import base64
import hmac
import hashlib
from datetime import datetime, timedelta


def create_access_token(data: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")

    expire = datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data["exp"] = expire.timestamp()
    payload_encoded = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    message = f"{header_encoded}.{payload_encoded}"
    signature = hmac.new(SECRET_KEY.encode(), message.encode(), hashlib.sha256)
    signature_encoded = base64.urlsafe_b64encode(signature.digest()).decode().rstrip("=")
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"


def verify_token(token: str) -> dict:
    try:
        # Разбиваем токен на части
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid token format")

        header_encoded, payload_encoded, signature_encoded = parts

        # Добавляем padding обратно для корректного сравнения
        def add_padding(data: str) -> str:
            return data + '=' * (-len(data) % 4)

        # Восстанавливаем оригинальную подпись
        signature = base64.urlsafe_b64decode(add_padding(signature_encoded))

        # Вычисляем ожидаемую подпись
        message = f"{header_encoded}.{payload_encoded}"
        expected_signature = hmac.new(
            SECRET_KEY.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()

        # Сравниваем бинарные данные, а не строки
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Invalid signature")

        # Декодируем payload
        payload = base64.urlsafe_b64decode(add_padding(payload_encoded)).decode()
        payload_data = json.loads(payload)

        if "exp" not in payload_data:
            raise ValueError("Token expiration missing")

        if datetime.now(UTC).timestamp() > payload_data["exp"]:
            raise ValueError("Token expired")

        return payload_data

    except Exception as e:
        raise ValueError(f"Token verification failed: {str(e)}")


# ================== Утилиты ==================

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# ================== База данных ==================

async def get_db_connection():
    return await aiomysql.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        db=MYSQL_DB,
        cursorclass=aiomysql.DictCursor
    )

async def init_db():
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            await cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    hashed_password VARCHAR(255) NOT NULL,
                    role VARCHAR(50) DEFAULT 'student'
                )
            ''')
            await cursor.execute('''
                CREATE TABLE IF NOT EXISTS profiles (
                    user_id INT PRIMARY KEY,
                    full_name TEXT NOT NULL,
                    work_place TEXT,
                    location TEXT,
                    bio TEXT,
                    photo_url TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')

            await cursor.execute('''
                CREATE TABLE IF NOT EXISTS classes (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(50) NOT NULL,
                    academic_year VARCHAR(20) NOT NULL
                )
            ''')

            await cursor.execute('''
                CREATE TABLE IF NOT EXISTS class_students (
                    class_id INT NOT NULL,
                    student_id INT NOT NULL,
                    PRIMARY KEY (class_id, student_id),
                    FOREIGN KEY (class_id) REFERENCES classes(id),
                    FOREIGN KEY (student_id) REFERENCES users(id)
                )
            ''')

            await cursor.execute('''
                CREATE TABLE IF NOT EXISTS class_teachers (
                    class_id INT NOT NULL,
                    teacher_id INT NOT NULL,
                    PRIMARY KEY (class_id, teacher_id),
                    FOREIGN KEY (class_id) REFERENCES classes(id),
                    FOREIGN KEY (teacher_id) REFERENCES users(id)
                )
            ''')

            await cursor.execute('''
                CREATE TABLE IF NOT EXISTS subjects (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) UNIQUE NOT NULL
                )
            ''')

            await cursor.execute('''
                CREATE TABLE IF NOT EXISTS grades (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    student_id INT NOT NULL,
                    subject_id INT NOT NULL,
                    value INT NOT NULL,
                    date DATE NOT NULL,
                    teacher_id INT NOT NULL,
                    FOREIGN KEY (student_id) REFERENCES users(id),
                    FOREIGN KEY (subject_id) REFERENCES subjects(id),
                    FOREIGN KEY (teacher_id) REFERENCES users(id)
                )
            ''')

            await cursor.execute('''
                CREATE TABLE IF NOT EXISTS homeworks (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    class_id INT NOT NULL,
                    subject_id INT NOT NULL,
                    due_date DATE NOT NULL,
                    description TEXT NOT NULL,
                    teacher_id INT NOT NULL,
                    FOREIGN KEY (class_id) REFERENCES classes(id),
                    FOREIGN KEY (subject_id) REFERENCES subjects(id),
                    FOREIGN KEY (teacher_id) REFERENCES users(id)
                )
            ''')
            await conn.commit()
    finally:
        conn.close()

async def get_user(username: str) -> Optional[UserInDB]:
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            await cursor.execute("SELECT id, username, hashed_password, role FROM users WHERE username=%s", (username,))
            user = await cursor.fetchone()
            if user:
                return UserInDB(**user)
            return None
    finally:
        conn.close()

async def create_user(username: str, hashed_password: str):
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            try:
                await cursor.execute(
                    "INSERT INTO users (username, hashed_password) VALUES (%s, %s)",
                    (username, hashed_password)
                )
                await conn.commit()
                return True
            except aiomysql.IntegrityError:
                return False
    finally:
        conn.close()

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = verify_token(token)
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except Exception:
        raise credentials_exception
    user = await get_user(username)
    if user is None:
        raise credentials_exception
    return user

# ================== FastAPI App ==================

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(lifespan=lifespan)

# ================== Роуты ==================

@app.post("/register")
async def register(user: UserCreate):
    hashed_password = get_password_hash(user.password)
    success = await create_user(user.username, hashed_password)
    if not success:
        raise HTTPException(status_code=400, detail="User already exists")
    return {"message": "User created successfully"}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await get_user(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/protected")
async def protected(current_user: User = Depends(get_current_user)):
    return {"message": f"Welcome, {current_user.username}!", "status": "authenticated"}

app.mount("/static", StaticFiles(directory=PROFILE_PHOTOS_DIR), name="static")

@app.post("/profile/photo")
async def upload_photo(
    file: UploadFile = File(...),
    current_user: UserInDB = Depends(get_current_user)
):
    file_extension = file.filename.split(".")[-1].lower()
    if file_extension not in ["jpg", "jpeg", "png"]:
        raise HTTPException(status_code=400, detail="Unsupported file type")

    file_name = f"{current_user.username}.{file_extension}"
    file_path = os.path.join(PROFILE_PHOTOS_DIR, file_name)

    # Удалим старые фото пользователя с другим расширением
    for ext in ["jpg", "jpeg", "png"]:
        old_file = os.path.join(PROFILE_PHOTOS_DIR, f"{current_user.username}.{ext}")
        if os.path.exists(old_file):
            os.remove(old_file)

    # Запись нового файла
    with open(file_path, "wb") as buffer:
        content = await file.read()
        buffer.write(content)

    photo_url = f"/static/profile_photos/{file_name}"
    return {"photo_url": photo_url, "message": "Photo uploaded successfully"}
from fastapi.responses import FileResponse

@app.get("/profile/photo")
async def get_profile_photo(current_user: UserInDB = Depends(get_current_user)):
    for ext in ["jpg", "jpeg", "png"]:
        file_name = f"{current_user.username}.{ext}"
        file_path = os.path.join(PROFILE_PHOTOS_DIR, file_name)
        if os.path.exists(file_path):
            media_type = f"image/{'jpeg' if ext in ['jpg', 'jpeg'] else 'png'}"
            return FileResponse(file_path, media_type=media_type)
    raise HTTPException(status_code=404, detail="Profile photo not found")


@app.get("/verify-token")
async def verify_token_endpoint(
    current_user: User = Depends(get_current_user)
):
    new_token = create_access_token(data={"sub": current_user.username})
    return {
        "status": "authenticated",
        "username": current_user.username,
        "role": getattr(current_user, "role", "student"),
        "access_token": new_token,
        "token_type": "bearer"
    }



@app.get("/profile/info")
async def get_profile_data(current_user: UserInDB = Depends(get_current_user)):
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            await cursor.execute("SELECT full_name, work_place, location, bio FROM profiles WHERE user_id = %s", (current_user.username,))
            profile = await cursor.fetchone()

            if profile:
                return profile
            else:
                raise HTTPException(status_code=404, detail="Profile not found")
    finally:
        conn.close()


@app.post("/profile/full-update")
async def update_full_profile(
    full_name: str = Form(...),
    work_place: str = Form(...),
    location: str = Form(...),
    bio: str = Form(...),
    file: Optional[UploadFile] = File(None),
    current_user: UserInDB = Depends(get_current_user)
):
    # Обновить текстовые поля профиля
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            await cursor.execute("SELECT * FROM profiles WHERE user_id = %s", (current_user.username,))
            exists = await cursor.fetchone()

            if exists:
                await cursor.execute("""
                    UPDATE profiles
                    SET full_name = %s, work_place = %s, location = %s, bio = %s
                    WHERE user_id = %s
                """, (full_name, work_place, location, bio, current_user.username))
            else:
                await cursor.execute("""
                    INSERT INTO profiles (user_id, full_name, work_place, location, bio)
                    VALUES (%s, %s, %s, %s, %s)
                """, (current_user.id, full_name, work_place, location, bio))

        await conn.commit()

        # Обработка фото
        if file:
            ext = file.filename.split('.')[-1].lower()
            if ext not in ["jpg", "jpeg", "png"]:
                raise HTTPException(status_code=400, detail="Unsupported file type")

            # Удалим старые
            for e in ["jpg", "jpeg", "png"]:
                old_path = os.path.join(PROFILE_PHOTOS_DIR, f"{current_user.username}.{e}")
                if os.path.exists(old_path):
                    os.remove(old_path)

            path = os.path.join(PROFILE_PHOTOS_DIR, f"{current_user.username}.{ext}")
            with open(path, "wb") as f:
                f.write(await file.read())

        return {"message": "Profile and photo updated"}

    finally:
        conn.close()

@app.get("/classes", response_model=list[ClassItem])
async def get_classes(current_user: UserInDB = Depends(get_current_user)):
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            await cursor.execute("""
                SELECT c.name, COUNT(u.id) AS student_count
                FROM classes c
                LEFT JOIN users u ON u.role = 'student' AND u.username LIKE CONCAT(c.name, '%')
                GROUP BY c.name
            """)
            result = await cursor.fetchall()
            return result
    finally:
        conn.close()


@app.get("/subject-scores/{subject_name}", response_model=list[dict])
async def get_student_scores_by_subject(
        subject_name: str,
        current_user: UserInDB = Depends(get_current_user)
):
    """
    Возвращает список учеников и их баллы по указанному предмету.
    Формат ответа:
    [
        {
            "student_id": int,
            "student_name": str,
            "scores": list[int],
            "average_score": float
        },
        ...
    ]
    """
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            # 1. Проверяем существование предмета
            await cursor.execute(
                "SELECT id FROM subjects WHERE name = %s",
                (subject_name,)
            )
            subject = await cursor.fetchone()
            if not subject:
                raise HTTPException(
                    status_code=404,
                    detail="Subject not found"
                )

            # 2. Получаем всех студентов и их оценки по предмету
            await cursor.execute("""
                SELECT 
                    u.id AS student_id,
                    p.full_name AS student_name,
                    GROUP_CONCAT(g.value ORDER BY g.date) AS scores
                FROM 
                    users u
                JOIN 
                    profiles p ON u.id = p.user_id
                LEFT JOIN 
                    grades g ON u.id = g.student_id AND g.subject_id = %s
                WHERE 
                    u.role = 'student'
                GROUP BY 
                    u.id, p.full_name
            """, (subject['id'],))

            students = await cursor.fetchall()

            # 3. Форматируем результат
            result = []
            for student in students:
                scores = []
                if student['scores']:
                    scores = list(map(int, student['scores'].split(',')))

                avg_score = 0.0
                if scores:
                    avg_score = round(sum(scores) / len(scores), 2)

                result.append({
                    "student_id": student['student_id'],
                    "student_name": student['student_name'],
                    "scores": scores,
                    "average_score": avg_score
                })

            # Сортируем по среднему баллу (по убыванию)
            result.sort(key=lambda x: x['average_score'], reverse=True)

            return result

    finally:
        conn.close()


@app.get("/student-scores-full", response_model=list[dict])
async def get_all_student_scores(current_user: UserInDB = Depends(get_current_user)):
    """
    Возвращает список учеников с их оценками по всем предметам.
    Формат:
    [
        {
            "student_id": int,
            "student_name": str,
            "grades": [
                {
                    "subject": str,
                    "value": int,
                    "date": str
                },
                ...
            ]
        },
        ...
    ]
    """
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            await cursor.execute("""
                SELECT 
                    u.id AS student_id,
                    p.full_name AS student_name,
                    s.name AS subject,
                    g.value,
                    g.date
                FROM users u
                JOIN profiles p ON u.id = p.user_id
                JOIN grades g ON u.id = g.student_id
                JOIN subjects s ON s.id = g.subject_id
                WHERE u.role = 'student'
                ORDER BY u.id, g.date
            """)
            rows = await cursor.fetchall()

            result = []
            current_student = None
            last_id = None

            for row in rows:
                if row['student_id'] != last_id:
                    if current_student:
                        result.append(current_student)
                    current_student = {
                        "student_id": row['student_id'],
                        "student_name": row['student_name'],
                        "grades": []
                    }
                    last_id = row['student_id']

                current_student["grades"].append({
                    "subject": row["subject"],
                    "value": row["value"],
                    "date": row["date"].isoformat() if hasattr(row["date"], "isoformat") else str(row["date"])
                })

            if current_student:
                result.append(current_student)

            return result
    finally:
        conn.close()



# ================== Запуск ==================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8001)
