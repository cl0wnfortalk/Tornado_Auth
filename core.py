import asyncio 
import atexit 
import bcrypt 
import datetime 
import os 
import logging
import asyncpg
import smtplib
import json 
import jwt 
import tornado 
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from asyncpg.pool import Pool 
from datetime import datetime as dt 
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from utils import hash_password
from utils import user_data_validator, login_data_validator
from utils import generate_verification_code
from utils import generate_jwt_token, generate_jwt_refresh_token, is_token_expired
from utils import generate_reset_token, verify_reset_token
from utils import generate_temp_jwt_token

# настройка логгера 
logger = logging.getLogger(__name__)

logging.basicConfig(
    filename='logs/logs.log',
    encoding='utf-8',
    level=logging.DEBUG, 
)

#  получение данных из ENV 
load_dotenv()

class CredentialsError(Exception):
    pass 

def get_creds(cred:str):
    if not isinstance(cred, str):
        raise TypeError("cred parameter must be str")
    cred = os.getenv(cred)
    if cred is None:
        logger.critical(f"{dt.now()}: {cred} is not available")
        raise CredentialsError(f"Cannot get {cred} from ENV")
    return cred 

app_secret_key = get_creds("APP_SECRET_KEY")
pg_username = get_creds("DB_USERNAME")
pg_password = get_creds("DB_PASSWORD")
mail_password = get_creds("MAIL_PASSWORD")
mail_sender = get_creds("MAIL_SENDER")
reset_secret_key = get_creds("RESET_TOKEN_SECRET_KEY")

# создание пула PGSQL
DB_CONFIG = {
    "user": pg_username,
    "password": pg_password,
    "database": "postgres",
    "host": "localhost",
    "port": "5432",
    "min_size": 5,   
    "max_size": 20,   
    "max_queries": 50000,  
    "max_inactive_connection_lifetime": 300,  
}

db_pool: Pool = None

async def create_db_pool():
    global db_pool
    db_pool = await asyncpg.create_pool(**DB_CONFIG)
    logger.info(f"{dt.now()}: Database connection pool created")

async def close_db_pool():
    global db_pool
    if db_pool:
        await db_pool.close()
        logger.info(f"{dt.now()}: Database connection pool closed")

# создание таблиц для хранения данных 
async def create_tables_if_not_exist():
    """
    Создает необходимые таблицы если не созданы 
    """
    try:
        async with db_pool.acquire() as conn:
            # Создание таблицы users
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    bio TEXT,
                    profile_picture_url VARCHAR(255),
                    is_active BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT NOW(),
                    expired_date TIMESTAMP DEFAULT (now() + '00:05:00'::interval)
                )
            """)
            
            # Создание таблицы mail_activation
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS mail_activation (
                    id SERIAL PRIMARY KEY,
                    mail VARCHAR(255) NOT NULL,
                    code VARCHAR(6) NOT NULL,
                    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
                    expired_date TIMESTAMP DEFAULT (now() + '00:05:00'::interval)
                )
            """)
            
            # Создание таблицы refresh_tokens
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
                    token VARCHAR(255) NOT NULL,
                    expires_at TIMESTAMP NOT NULL
                )
            """)
            
            logger.info(f"{dt.now()}: Tables created/verified successfully")
            
    except Exception as e:
        logger.error(f"{dt.now()}: Error creating tables - {e}")
        raise

# настройка mail 
def send_mail(email:str, subject:str, message:str):
    """Отправляет код подтверждения электронной почты пользователю"""

    msg = MIMEMultipart()
    msg['From'] = mail_sender
    msg['To'] = email 
    msg['Subject'] = subject
    msgbody = message 
    msg.attach(MIMEText(msgbody, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)  
        server.starttls() 
        server.login(mail_sender, mail_password)  
        server.send_message(msg) 
    except Exception as e:
        logger.error(f"{dt.now()}: Mail sending error: {e}") 
    finally:
        server.quit() 

# код пользователя если забыл пароль 

# функция сохранения пользователя 
async def insert_user(username: str, email: str, hashed_password: str) -> int | None:
    """
    Сохраняет нового пользователя в БД и возвращает его ID если операция успешна
    """
    try:
        async with db_pool.acquire() as conn:
            statement = """
                INSERT INTO users (username, email, password_hash) 
                VALUES ($1, $2, $3) 
                RETURNING user_id
            """
            user_id = await conn.fetchval(statement, username, email, hashed_password)
            return user_id
            
    except asyncpg.UniqueViolationError as e:
        logger.error(f"{dt.now()}: User already exists - {e}")
        return None
    except asyncpg.PostgresError as e:
        logger.error(f"{dt.now()}: Database error - {e}")
        return None
    except Exception as e:
        logger.error(f"{dt.now()}: Unexpected error - {e}")
        return None

async def insert_mail_activation(email: str, code: str, user_id: int) -> None:
    """
    Сохраняет временный код для активации электронного адреса в БД
    """
    try:
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                query = """
                INSERT INTO mail_activation (mail, code, user_id) 
                VALUES ($1, $2, $3)
                """
                await conn.execute(query, email, code, user_id)
    except Exception as e:
        logger.error(f"{dt.now()}: Ошибка при сохранении кода активации: {e}")
        raise  

# настройка веб-страницы для регистрации нового пользователя
class RegistrationHandler(tornado.web.RequestHandler):
    async def get(self):
        await self.render("assets/templates/registration.html")

    async def post(self):
        if self.request.headers['Content-Type'] == 'application/json':
            self.args = json.loads(self.request.body)
            if user_data_validator(self.args):
                username = self.args.get('username', False)
                password = self.args.get('password', False)
                confirm = self.args.get('confirm', False)
                email = self.args.get('email', False)
                if username and password and confirm and email:
                    password = password.strip()
                    username = username.strip()
                    email = email.strip()
                    confirm = confirm.strip()
                    if password != confirm:
                        self.set_status(400)
                        self.write('Введенные пароли не совпадают')
                        return 
                    else:
                        # хэширование пароля
                        hashed_password = hash_password(password)
                        
                        # отправить код для подтверждения почты 
                        subject = 'Подтверждение электронной почты'
                        code = generate_verification_code()
                        msgbody = f"Ваш код: {code}"
                        send_mail(email, subject, msgbody)
                        user_id = None 
                        # добавление пользователя 
                        try:
                            user_id = await insert_user(username, email, hashed_password)
                        except Exception as e:
                            logger.error(f"{dt.now()}: Ошибка при сохранении пользователя: {e}")

                        # внести в БД код и почту пользователя 
                        try:
                            if user_id is not None:
                                await insert_mail_activation(email, code, user_id)
                            else:
                                logger.error(f"{dt.now()}: ID пользователя не найден")
                                self.set_status(400)
                                self.write('Ошибка при отправлении данных - не найден ID пользователя')
                                return 
                        except Exception as e:
                            logger.error(f"{dt.now()}: Код активации не сохранен в БД {e}")
                else:
                    self.set_status(400)
                    self.write('Получены некорректные данные либо данные отсутствуют')
                    return 
            else:
                self.set_status(400)
                self.write('Получен некорректный тип данных')
                return 
        else:
            self.set_status(400)
            self.write('Получен некорректный тип данных')
            return 
        
async def is_mail_verified(email: str, code: str) -> bool:
    """
    Проверяет, соответствует ли код подтверждения для указанного email.
    Если соответствует - удаляет запись из таблицы mail_activation и возвращает True.
    В противном случае возвращает False.
    """
    global db_pool  
    
    try:
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                server_code = await conn.fetchval(
                    "SELECT code FROM mail_activation WHERE mail = $1",
                    email
                )
                
                if server_code is None:
                    logger.warning(f"{dt.now()}: No activation code found for email: {email}")
                    return False
                
                if server_code == code:
                    await conn.execute(
                        "DELETE FROM mail_activation WHERE mail = $1",
                        email
                    )
                    return True
                
                logger.warning(f"{dt.now()}: Invalid activation code for email: {email}")
                return False
                
    except Exception as e:
        logger.error(f"{dt.now()}: Error verifying email {email}: {e}")
        return False
    
async def activate_user(email: str) -> None:
    """
    Активирует пользователя в базе данных по email.
    """
    try:
        async with db_pool.acquire() as conn:  
            async with conn.transaction(): 
                await conn.execute(
                    "UPDATE users SET is_active = true WHERE email = $1",
                    email
                )
                
    except Exception as e:
        logger.error(f"{dt.now()}: Failed to activate user {email}. Error: {e}")
        raise  

class EmailVerification(tornado.web.RequestHandler):
    async def post(self):
        if self.request.headers['Content-Type'] == 'application/json':
            self.args = json.loads(self.request.body)
            code = self.args.get('code', False)
            email = self.args.get('email', False)
            if email and code:
                code = code.strip()
                email = email.strip()
                if len(code) != 6:
                    self.set_status(400)
                    self.write('Код введен неверно')
                    return 
                else:
                    try:
                        code_checking = await is_mail_verified(email, code)
                        if code_checking:
                            # активировать пользователя 
                            try:
                                await activate_user(email)
                                self.set_status(301)
                                await self.redirect('/login')
                            except Exception as e:
                                logger.error(f"{dt.now()}: Failed to activate user {email}. Error: {e}")
                                return 
                    except Exception as e:
                        logger.error(f"{dt.now()}: Email verification failed for user {email}. Error: {e}")
                        return 
        else:
            self.set_status(400)
            self.write('Получен некорректный тип данных')
            return 

# Вход в аккаунт, проверка данных пользователя, создание сессии 

async def insert_refresh_token(username: str, token: str) -> None:
    """Вставляет либо обновляет refresh токен в БД"""
    try:
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                user_id = await conn.fetchval(
                    "SELECT user_id FROM users WHERE username = $1 AND is_active = true",
                    username
                )

                await conn.execute(
                    """
                    DELETE FROM refresh_tokens WHERE user_id = $1
                    """,
                    user_id
                )
                
                if user_id is not None:
                    exp_date = dt.now() + datetime.timedelta(days=30)
                    
                    await conn.execute(
                        """
                        INSERT INTO refresh_tokens (user_id, token, expires_at)
                        VALUES ($1, $2, $3)
                        """,
                        user_id, token, exp_date
                    )
                    
                    logger.debug(f"{dt.now()}: Refresh token updated for user {username}")
                else:
                    logger.warning(f"{dt.now()}: User {username} not found or inactive")
                    
    except Exception as e:
        logger.error(f"{dt.now()}: Error in insert_refresh_token: {e}")
        raise  

async def is_user_alive(username: str, password: str) -> bool:
    """
    Проверяет существование пользователя и соответствие пароля.
    """
    try:
        async with db_pool.acquire() as conn:
            query = """
            SELECT password_hash 
            FROM users 
            WHERE username = $1 AND is_active = true
            """
            
            hash_password = await conn.fetchval(query, username)
            
            if hash_password is not None:
                return bcrypt.checkpw(
                    password.encode('utf-8'), 
                    hash_password.encode('utf-8')
                )
        return False
    except Exception as e:
        logger.error(f"{dt.now()}: Error in is_user_alive: {e}")
        return False

# веб-страница для входа в аккаунт 
class LoginHandler(tornado.web.RequestHandler):
    async def get(self):
        self.set_status(200)
        await self.render("assets/templates/login.html")
    async def post(self):
        if self.request.headers['Content-Type'] == 'application/json':
            self.args = json.loads(self.request.body)
            if login_data_validator(self.args):
                username = self.args.get('username', False)
                password = self.args.get('password', False)
                if username and password:
                    password = password.strip()
                    username = username.strip()
                    # проверяем пользователя 
                    if await is_user_alive(username, password):
                        # создаем JWT токен и кидаем в cookies 
                        jwt = generate_jwt_token(username, app_secret_key)
                        self.set_cookie("jwt", jwt, httponly=True, secure=True, samesite='Lax')

                        # генерация refresh JWT токена 
                        refresh_token = generate_jwt_refresh_token(username, app_secret_key)
                        # сохранение refresh токена в БД 
                        try:
                            await insert_refresh_token(username, refresh_token)
                        except Exception as e:
                            logger.error(f"{dt.now()}: Could not get refresh token {e}")
                            self.set_status(400)
                            self.write("Ошибка токена. Попробуйте войти в профиль еще раз")
                            return
                        self.set_cookie("refresh", refresh_token, httponly=True, secure=True)
                        self.set_status(301)
                        self.redirect('/account')
                    else:
                        self.set_status(400)
                        self.write({"error":"Пароль или логин введены неверно"})
                else:
                    self.set_status(400)
                    self.write('Ошибка при входе в аккаунт')
                    return 
            else:
                self.set_status(400)
                self.write('Получены неполные данные либо данные отсутствуют')
                return 
        else:
            self.set_status(400)
            self.write('Получен некорректный тип данных')
            return 

# проверки JWT 

async def check_jwt_token(token):
    try:
        payload = jwt.decode(token, app_secret_key, algorithms=['HS256'])
        if is_token_expired(payload):
            logger.info("JWT token has expired")
            return None

        username = payload['sub']
        try:
            async with db_pool.acquire() as conn:
                result = await conn.fetchrow(
                    "SELECT username FROM users WHERE username = $1 AND is_active = true",
                    username
                )
                if result:
                    return result['username']  
                else:
                    logger.warning(f"User with username {username} not found or inactive")
                    return None
        except Exception as e:
            logger.error(f"Database error in check_jwt_token: {e}")
            return None
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token has expired")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invalid JWT token")
        return None


async def check_refresh_token(token):
    """Проверяет валидность refresh-токена и возвращает (is_valid, username, needs_new_refresh)."""
    try:
        payload = jwt.decode(token, app_secret_key, algorithms=['HS256'])
        username = payload['sub']
        exp = payload['exp']
        
        if datetime.datetime.now(datetime.timezone.utc).timestamp() > exp:
            return (False, None, False)
            
        async with db_pool.acquire() as conn:
            user = await conn.fetchrow(
                "SELECT user_id FROM users WHERE username = $1 AND is_active = true",
                username
            )
            if not user:
                return (False, None, False)
                
            db_token = await conn.fetchrow(
                """SELECT token, expires_at 
                FROM refresh_tokens 
                WHERE user_id = $1 AND expires_at > NOW()""",
                user['user_id']
            )

            
            if not db_token or db_token['token'] != token:
                return (False, None, False)
                
            need_new_refresh = (db_token['expires_at'] - datetime.datetime.now()).days < 7
            return (True, username, need_new_refresh)

    except jwt.ExpiredSignatureError:
        return (False, None, False)
    except jwt.InvalidTokenError:
        return (False, None, False)
    except Exception as e:
        logger.error(f"Error in check_refresh_token: {e}")
        return (False, None, False)

async def get_user_data(username):
    try:
        async with db_pool.acquire() as conn:
            result = await conn.fetchrow(
                """
                SELECT username, email, bio, created_at, profile_picture_url 
                FROM users 
                WHERE username = $1 AND is_active = true
                """,
                username
            )
            
            if result:
                return {
                    'username': result['username'],
                    'email': result['email'],
                    'bio': result['bio'],
                    'created_at': result['created_at'],
                    'profile_picture_url': result['profile_picture_url']
                }
            return None
    except Exception as e:
        logger.error(f"Error in get_user_data: {e}")
        return None

# декоратор для проверки аутентифицирован ли пользователь

def login_required(method):
    async def wrapper(self, *args, **kwargs):
        access_token = self.get_cookie('jwt')
        refresh_token = self.get_cookie('refresh')
        
        username = await check_jwt_token(access_token)
        
        if username is None and refresh_token:
            is_valid, new_username, need_new_refresh = await check_refresh_token(refresh_token)
            
            if is_valid:

                new_access_token = generate_jwt_token(new_username, app_secret_key)
                
                if need_new_refresh:
                    new_refresh_token = generate_jwt_refresh_token(new_username, app_secret_key)
                    await insert_refresh_token(new_username, new_refresh_token)
                    self.set_cookie("refresh", new_refresh_token, 
                                  httponly=True, secure=True, samesite='Lax')
                else:
                    new_refresh_token = refresh_token
                
                self.set_cookie("jwt", new_access_token, 
                              httponly=True, secure=True, samesite='Lax')
                username = new_username
                
                logger.info(f"Tokens refreshed for user {username}")
            else:
                self.clear_cookie('jwt')
                self.clear_cookie('refresh')
                self.redirect('/login')
                return

        if username is None:
            self.clear_cookie('jwt')
            self.clear_cookie('refresh')
            self.redirect('/login')
            return
            
        await method(self, *args, **kwargs)
    return wrapper

# выход из аккаунта 

class Logout(tornado.web.RequestHandler):
    @login_required
    async def post(self):
        self.clear_cookie("jwt")  
        self.clear_cookie("refresh")
        self.set_status(200)
        self.redirect('/login') 

# удаление аккаунта 

async def remove_user_from_users(username: str) -> bool:
    """
    Удаляет пользователя из базы данных по имени пользователя.
    """
    try:
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                result = await conn.execute(
                    "DELETE FROM users WHERE is_active = true AND username = $1",
                    username
                )
                
                if result == "DELETE 0":
                    logger.warning(f"{dt.now()}: User {username} not found or already inactive")
                    return False
                
                logger.info(f"{dt.now()}: Successfully removed user {username}")
                return True
                
    except Exception as e:
        logger.error(f"{dt.now()}: Error removing user {username}: {e}")
        return False

class DeleteAccount(tornado.web.RequestHandler):
    @login_required
    async def post(self):
        access_token = self.get_cookie("jwt")
        username = await check_jwt_token(access_token)

        try:
            await remove_user_from_users(username)
            self.set_status(200)
            self.clear_all_cookies()
            self.redirect("/signup")
        except Exception as e:
            logger.error(f"{dt.now()}: Error removing user {username}: {e}")
            self.set_status(401) 
            self.write('Не удалось удалить пользователя')

class TestPage(tornado.web.RequestHandler):
    @login_required
    async def get(self):
        access_token = self.get_cookie("jwt")
        try:
            username = await check_jwt_token(access_token)
        except Exception as e:
            logger.error(f"{dt.now()}: Error checking JWT {e}")
        try:
            user_data = await get_user_data(username)
            if user_data is None:
                self.write('Данные пользователя не получены. Перезагрузите страницу.')
                return
        except Exception as e:
            logger.error(f"{dt.now()}: Error getting user data {username}: {e}")
        return self.render("assets/templates/test.html", **user_data)

# восстановление пароля 
class RestorePassword(tornado.web.RequestHandler):
    async def get(self):
        self.render("assets/templates/restore_password.html")
        return
    async def post(self):
        if self.request.headers['Content-Type'] == 'application/json':
            self.args = json.loads(self.request.body)
            email = self.args["email"]
            if email:
                email = email.strip()
                reset_token = generate_reset_token(email, reset_secret_key)
                msgbody = f"Не переходите по ссылке если не запрашивали восстановление пароля http://127.0.0.1:8888/confirm/{reset_token}"
                subject = "Восстановление пароля в Protocols"
                send_mail(email, subject, msgbody)
                self.set_status(200)
                
            else:
                self.set_status(400)
                self.write({"error":"Email не получен"})
                return 
        else:
            self.set_status(400)
            self.write({"error":"Получен некорректный тип данных"})

# подтверждение по токену 
class ConfirmResetToken(tornado.web.RequestHandler):
    async def get(self, token):
        valid = verify_reset_token(token, reset_secret_key)
        if valid:
            # valid - это почтовый адрес клиента в виде строки
            temp_token = generate_temp_jwt_token(valid, app_secret_key)
            self.set_cookie("reset", temp_token, httponly=True, secure=True, samesite='Lax')
            self.set_status(200)
            self.render("assets/templates/new_password.html", email=valid)
        else:
            self.set_status(400)
            self.render("assets/templates/error.html")

# получение и сохранение нового пароля пользователя 

async def change_user_password(email: str, password: str):
    """
    Обновляет пароль пользователя в базе данных 
    """
    try:
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                result = await conn.execute(
                    "UPDATE users SET password_hash=$1 WHERE email=$2 AND is_active=true", 
                    password, email
                )
                
                if result == "UPDATE 0":
                    logger.warning(f"{dt.now()}: User {email} not found or already inactive")
                    return False
                
                logger.info(f"{dt.now()}: Successfully updated password for user {email}")
                return True
                
    except Exception as e:
        logger.error(f"{dt.now()}: Error updating password for user {email}: {e}")
        return False

def check_reset_token_temp_from_cookie(token, email):
    payload = jwt.decode(token, app_secret_key, algorithms=['HS256'])
    return payload['sub'] == email 

class NewPassword(tornado.web.RequestHandler):
    async def post(self):
        if self.request.headers['Content-Type'] == 'application/json':
            temp_token = self.get_cookie("reset")
            self.args = json.loads(self.request.body)
            password = self.args.get("password", False)
            email = self.args.get("email", False)
            if password and email:
                email = email.strip()
                if not check_reset_token_temp_from_cookie(temp_token, email):
                    self.set_status(400)
                    self.render("assets/templates/error.html")
                    return 
                password = password.strip()
                hashed_password = hash_password(password)
                try:
                    await change_user_password(email, hashed_password)
                except Exception as e:
                    logger.error(f"{dt.now()}: Error updating password for user {email}: {e}")
                    self.set_status(400)
                    self.write({"error":"Не удалось обновить пароль"})
                    return 
                self.set_status(200)
                self.clear_cookie("reset")
                self.redirect("/login")
                return
            else:
                self.set_status(400)
                self.write({"error":"Новый пароль или почта не получены"})
                return 
        else:
            self.set_status(400)
            self.write({"error":"Получен некорректный тип данных"})

# удаление неактивированных аккаунтов и кодов доступа

scheduler = AsyncIOScheduler()

async def delete_expired_data():
    try:
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "DELETE FROM users WHERE is_active=false AND expired_date < NOW()"
                )
                await conn.execute(
                    "DELETE FROM mail_activation WHERE expired_date < NOW()"
                )
    except Exception as e:
        logger.error(f"Cleanup error: {str(e)}")

async def start_scheduler():
    scheduler.add_job(
        delete_expired_data,
        'interval',
        minutes=1,
        max_instances=1
    )
    scheduler.start()
    logger.info("Scheduler started")
atexit.register(lambda: scheduler.shutdown())

# билдинг приложения 
async def initialize_db():
    try:
        await create_db_pool()
        await create_tables_if_not_exist()
        async with db_pool.acquire() as conn:
            await conn.fetch("SELECT 1")
        logger.info("Database initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False
    
async def make_app():
    if not await initialize_db():
        raise RuntimeError("Failed to initialize database")
    
    return tornado.web.Application([
        (r'/signup', RegistrationHandler),
        (r'/email-confirmation', EmailVerification),
        (r'/login', LoginHandler),
        (r'/account', TestPage),
        (r'/logout', Logout),
        (r'/delete-account', DeleteAccount),
        (r'/restore', RestorePassword),
        (r'/confirm/([^/]+)', ConfirmResetToken),
        (r'/new-password', NewPassword),
    ], 
    static_path="assets")

async def main():
    try:
        await initialize_db()
        await start_scheduler()  
        
        app = await make_app()
        app.listen(8888)
        logger.info("Server started on http://localhost:8888")
        
        while True:
            await asyncio.sleep(1)
            
    except Exception as e:
        logger.critical(f"Server failed: {str(e)}", exc_info=True)
    finally:
        await close_db_pool()
        scheduler.shutdown()
        logger.info("Server stopped gracefully")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")