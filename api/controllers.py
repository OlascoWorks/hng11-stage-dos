from flask import request, jsonify
from .models import User
from functools import wraps
from datetime import datetime, timedelta
import jwt, os,bcrypt

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        currentUser = None
        token = None

        if 'X-access-token' in request.cookies:
            token = request.cookies['X-access-token']

        # set to arbitrary value if token is not passed
        if not token:
            token = 'No-ToKeN1234'
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, os.environ.get('JWT_SECRET'), algorithms=["HS256"])
            expiration = data['exp']
            # covert expiration to datetime
            expiration = datetime.fromtimestamp(expiration)
            if expiration < datetime.now():
                return jsonify({
                    'message' : 'Token is expired!!',
                    'error' : str(e)
                }), 401
            else:
                currentUser = User.query.filter_by(userId=data['id']).first()
                access_token = request.cookies['X-access-token']
        except Exception as e:
            return jsonify({
                'message' : 'Token is invalid!!',
                'error' : str(e)
            }), 401
        
        # returns the current logged in users context to the routes
        return  f(currentUser, access_token, *args, **kwargs)
  
    return decorated

def validate_fields(fn, ln, email, password):
    if len(fn) < 1:  return False, ['firstName', 'first name is required']
    elif len(ln) < 1:  return False, ['lastName', 'last name is required']
    elif len(email) < 1:  return False, ['email', 'email is required']
    elif len(password) < 1:  return False, ['password', 'password is required']

    if User.query.filter_by(email=email).first():  return False, ['email', 'a user with this email already exits']

    return (True,)

def generate_access_token(data):
    access_code = jwt.encode(data, os.environ.get('JWT_SECRET'))
    return access_code

def check_password(password, user):
    if bcrypt.checkpw(password.encode('utf-8'), user.password):  return True
    else: return False