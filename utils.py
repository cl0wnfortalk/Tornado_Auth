import bcrypt 
import random 
import tzlocal 
import datetime 
import jwt 
from datetime import datetime as dt 
from itsdangerous import URLSafeTimedSerializer
from cerberus import Validator

# функция для хеширования пароля 
def hash_password(password:str):
    # генерация соли 
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

# валидация пользовательских данных
user_data_scheme_validator = {
    'username':{'type':'string', 'minlength': 5, 'maxlength': 50},
    'email':{'type':'string'},
    'password':{'type':'string', 'minlength': 11, 'maxlength': 254},
    'confirm':{'type':'string', 'minlength': 11, 'maxlength': 254},
}

user_data_validator = Validator(user_data_scheme_validator)

login_data_scheme_validator = {
    'username':{'type':'string', 'minlength': 5, 'maxlength': 50},
    'password':{'type':'string', 'minlength': 11, 'maxlength': 254},
}

login_data_validator = Validator(login_data_scheme_validator)

def generate_verification_code():
    nums = list(range(0,9))
    code = "".join([str(random.choice(nums)) for _ in range(6)])
    return code 

def generate_jwt_token(username, app_secret_key):
    """Генерирует JWT access токен с учетом локального времени."""
    local_timezone = tzlocal.get_localzone() 

    now = dt.now()

    expiration_time = now + datetime.timedelta(minutes=30)

    utc_expiration_time = expiration_time.astimezone(datetime.timezone.utc)

    timestamp = int(utc_expiration_time.timestamp())

    payload = {
        'sub': username,
        'exp': timestamp
    }

    jwt_token = jwt.encode(payload, app_secret_key, algorithm='HS256')
    return jwt_token

def generate_jwt_refresh_token(username, app_secret_key):
    """Генерирует JWT refresh токен"""
    import datetime 
    jwt_token = jwt.encode({
        'sub': username,
        'exp': dt.now() + datetime.timedelta(days=30)
    }, app_secret_key, algorithm='HS256')
    return jwt_token

def is_token_expired(payload):
    if 'exp' in payload:
        exp = payload['exp']
        current_time = int(datetime.datetime.now().timestamp())
        return current_time > exp
    return True 

# формирование токена восстановления пароля (ссылка)
def generate_reset_token(email, restore_secret_key):
    serializer = URLSafeTimedSerializer(restore_secret_key)
    return serializer.dumps(email, salt="fjcofbrhcynryfh46fheyfbn")

def verify_reset_token(token, restore_secret_key, max_age=3600):
    serializer = URLSafeTimedSerializer(restore_secret_key)
    try:
        email = serializer.loads(token, salt="fjcofbrhcynryfh46fheyfbn", max_age=max_age)
        return email 
    except:
        return None 
    
def generate_temp_jwt_token(email, app_secret_key):
    """Генерирует JWT access токен с учетом локального времени."""
    local_timezone = tzlocal.get_localzone() 

    now = dt.now()

    expiration_time = now + datetime.timedelta(minutes=5)

    utc_expiration_time = expiration_time.astimezone(datetime.timezone.utc)

    timestamp = int(utc_expiration_time.timestamp())

    payload = {
        'sub': email,
        'exp': timestamp
    }

    jwt_token = jwt.encode(payload, app_secret_key, algorithm='HS256')
    return jwt_token