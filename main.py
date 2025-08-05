import os
from contextlib import asynccontextmanager
from datetime import UTC
from enum import Enum
from typing import Optional, List

import aiomysql
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from starlette.staticfiles import StaticFiles

# ================== Конфигурация ==================
SECRET_KEY = "304f1388f317fe2e917a1df468144def7f60586ba96dc80b07d26c68cae00fab"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 604800



ENCRYPTION_KEY = "ICkoftk-wbOx89vzo2nuGkPatHZCQ1IKBVpFdRJ1F4k="  # Храни в .env
fernet = Fernet(ENCRYPTION_KEY.encode())

def encrypt_message(message: str) -> str:
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message: str) -> str:
    return fernet.decrypt(encrypted_message.encode()).decode()


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


class StudentResponse(BaseModel):
    id: int  # Измените id на user_id
    full_name: str
    work_place: Optional[str] = None  # Соответствует полю в БД
    location: Optional[str] = None
    bio: Optional[str] = None
    photo_url: Optional[str] = None

class StudentWithGradesResponse(StudentResponse):
    grades: List[dict] = []
    average_score: Optional[float] = None


class UserRole(str, Enum):
    student = "student"
    teacher = "teacher"



from pydantic import BaseModel
from typing import Optional

class UserResponse(BaseModel):
    id: int
    full_name: str
    class_name: Optional[str] = None  # для студентов
    photo_url: Optional[str] = None

    work_place: Optional[str] = None  # для учителей
    location: Optional[str] = None
    subject: Optional[str] = None
    classes: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

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
            await cursor.execute('''
                CREATE TABLE IF NOT EXISTS conversations (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user1_id INT NOT NULL,
                    user2_id INT NOT NULL,
                    user_min_id INT NOT NULL,
                    user_max_id INT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY unique_pair (user_min_id, user_max_id),
                    FOREIGN KEY (user1_id) REFERENCES users(id),
                    FOREIGN KEY (user2_id) REFERENCES users(id)
                )
            ''')
            await cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    conversation_id INT NOT NULL,
                    sender_id INT NOT NULL,
                    content TEXT NOT NULL, 
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (conversation_id) REFERENCES conversations(id),
                    FOREIGN KEY (sender_id) REFERENCES users(id)
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
        file_name = f"{current_user.id}.{ext}"
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
        "token_type": "bearer",
        "user_id": current_user.id
    }



@app.get("/profile/info")
async def get_profile_data(current_user: UserInDB = Depends(get_current_user)):
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            await cursor.execute("""
                            SELECT 
                                TRIM(BOTH '"' FROM full_name) AS full_name,
                                TRIM(BOTH '"' FROM work_place) AS work_place,
                                TRIM(BOTH '"' FROM location) AS location,
                                TRIM(BOTH '"' FROM bio) AS bio
                            FROM profiles 
                            WHERE user_id = %s
                        """, (current_user.id,))
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

            await cursor.execute("SELECT * FROM profiles WHERE user_id = %s", (current_user.id,))
            exists = await cursor.fetchone()
            if exists:
                await cursor.execute("""
                    UPDATE profiles
                    SET full_name = %s, work_place = %s, location = %s, bio = %s
                    WHERE user_id = %s
                """, (full_name, work_place, location, bio, current_user.id))
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
                old_path = os.path.join(PROFILE_PHOTOS_DIR, f"{current_user.id}.{e}")
                if os.path.exists(old_path):
                    os.remove(old_path)

            path = os.path.join(PROFILE_PHOTOS_DIR, f"{current_user.id}.{ext}")
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

@app.get("/users/all", response_model=List[UserResponse])
async def get_all_users(
    role: UserRole,
    page: int = 1,
    per_page: int = 20,
    current_user: UserInDB = Depends(get_current_user)
):
    """
    Получить всех пользователей по роли (ученики или преподаватели)
    """
    conn = await get_db_connection()
    try:
        async with conn.cursor(aiomysql.DictCursor) as cursor:
            offset = (page - 1) * per_page

            if role == UserRole.student:
                await cursor.execute("""
                    SELECT 
                        u.id,
                        p.full_name,
                        (SELECT c.name FROM classes c 
                         JOIN class_students cs ON c.id = cs.class_id 
                         WHERE cs.student_id = u.id LIMIT 1) as class_name,
                        p.photo_url
                    FROM users u
                    JOIN profiles p ON u.id = p.user_id
                    WHERE u.role = 'student'
                    LIMIT %s OFFSET %s
                """, (per_page, offset))

            elif role == UserRole.teacher:
                await cursor.execute("""
                    SELECT 
                        u.id,
                        p.full_name,
                        p.work_place,
                        p.location,
                        (SELECT GROUP_CONCAT(c.name SEPARATOR ', ') 
                         FROM class_teachers ct 
                         JOIN classes c ON ct.class_id = c.id 
                         WHERE ct.teacher_id = u.id) as classes,
                        p.photo_url
                    FROM users u
                    JOIN profiles p ON u.id = p.user_id
                    WHERE u.role = 'teacher'
                    LIMIT %s OFFSET %s
                """, (per_page, offset))

            users = await cursor.fetchall()
            return users

    finally:
        conn.close()



class MessageIn(BaseModel):
    receiver_id: int
    content: str

class SendMessageRequest(BaseModel):
    receiver_id: int
    content: str

@app.post("/messages/send")
async def send_message(
    data: SendMessageRequest,
    current_user: UserInDB = Depends(get_current_user)
):
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            user1_id = current_user.id
            user2_id = data.receiver_id
            user_min_id = min(user1_id, user2_id)
            user_max_id = max(user1_id, user2_id)

            # 1. Поиск существующей беседы
            await cursor.execute("""
                SELECT id FROM conversations
                WHERE user_min_id = %s AND user_max_id = %s
            """, (user_min_id, user_max_id))
            conv = await cursor.fetchone()

            # 2. Если беседы нет — создать
            if not conv:
                await cursor.execute("""
                    INSERT INTO conversations (user1_id, user2_id, user_min_id, user_max_id)
                    VALUES (%s, %s, %s, %s)
                """, (user1_id, user2_id, user_min_id, user_max_id))
                await conn.commit()
                conversation_id = cursor.lastrowid
            else:
                conversation_id = conv["id"]

            # 3. Зашифровать сообщение
            encrypted = encrypt_message(data.content)

            # 4. Сохранить сообщение
            await cursor.execute("""
                INSERT INTO messages (conversation_id, sender_id, content)
                VALUES (%s, %s, %s)
            """, (conversation_id, current_user.id, encrypted))
            await conn.commit()

            return {"status": "ok", "conversation_id": conversation_id}

    finally:
        conn.close()



@app.get("/messages/{user_id}")
async def get_messages(user_id: int, current_user: UserInDB = Depends(get_current_user)):
    conn = await get_db_connection()
    try:
        user_min_id = min(current_user.id, user_id)
        user_max_id = max(current_user.id, user_id)

        async with conn.cursor() as cursor:
            # найти conversation
            await cursor.execute("""
                SELECT id FROM conversations
                WHERE user_min_id = %s AND user_max_id = %s
            """, (user_min_id, user_max_id))
            conv = await cursor.fetchone()
            if not conv:
                return []

            conversation_id = conv["id"]

            # получить сообщения
            await cursor.execute("""
                SELECT sender_id, content, created_at
                FROM messages
                WHERE conversation_id = %s
                ORDER BY created_at
            """, (conversation_id,))

            rows = await cursor.fetchall()

            # расшифровать каждое сообщение
            messages = []
            for row in rows:
                try:
                    decrypted = decrypt_message(row["content"])
                except Exception as e:
                    decrypted = "[не удалось расшифровать]"
                messages.append({
                    "sender_id": row["sender_id"],
                    "content": decrypted,
                    "created_at": row["created_at"].isoformat()
                })

            return messages
    finally:
        conn.close()


@app.get("/conversations")
async def get_user_conversations(current_user: UserInDB = Depends(get_current_user)):
    conn = await get_db_connection()
    try:
        async with conn.cursor(aiomysql.DictCursor) as cursor:
            await cursor.execute("""
                SELECT c.id AS conversation_id,
                       u.id AS user_id,
                       p.full_name,
                       p.photo_url,
                       m.content,
                       m.created_at,
                       m.sender_id
                FROM conversations c
                JOIN users u ON u.id = IF(c.user1_id = %s, c.user2_id, c.user1_id)
                JOIN profiles p ON p.user_id = u.id
                LEFT JOIN (
                    SELECT conversation_id, MAX(created_at) AS max_time
                    FROM messages
                    GROUP BY conversation_id
                ) latest ON latest.conversation_id = c.id
                LEFT JOIN messages m ON m.conversation_id = c.id AND m.created_at = latest.max_time
                WHERE %s IN (c.user1_id, c.user2_id)
                ORDER BY m.created_at DESC
            """, (current_user.id, current_user.id))

            rows = await cursor.fetchall()
            return [{
                "conversation_id": row["conversation_id"],
                "user_id": row["user_id"],
                "full_name": row["full_name"],
                "photo_url": row["photo_url"],
                "last_message": row["content"],
                "last_time": row["created_at"],
                "last_sender_id": row["sender_id"]
            } for row in rows if row["content"]]
    finally:
        conn.close()



# ================== Запуск ==================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8001)
