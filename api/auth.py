from flask import Blueprint, request, jsonify, make_response
from .models import User, Organisation
from .controllers import validate_fields, generate_access_token, check_password
from datetime import datetime, timedelta
import bcrypt, uuid

auth = Blueprint('auth', __name__)
from api import db

@auth.route('/register', methods=['POST'])
def register():
    try:
        request_data = request.get_json()
        first_name = request_data['firstName']
        last_name = request_data['lastName']
        email = request_data['email']
        password = request_data['password']
        phone = request_data['phone']

        if not first_name or not last_name or not email or not password:
            return jsonify({
                "status": "Bad request",
                "message": "Registration unsuccessful",
                "statusCode": 400
            }), 400

        validation = validate_fields(first_name, last_name, email, password)

        if validation[0] != True:
            return jsonify({
                "errors": [
                    {
                        "field": validation[1][0],
                        "message": validation[1][1]
                    },
                ]
            }), 422
        
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        user_id = str(uuid.uuid4().hex)
        data = {
            "id": user_id,
            "exp": datetime.now() + timedelta(minutes=3)
        }

        new_user = User(id=user_id, firstName=first_name, lastName=last_name, email=email, password=hashed_password, phone=phone)
        db.session.add(new_user)
        db.session.commit()

        access_token = generate_access_token(data)
        
        org_id = str(uuid.uuid4().hex)
        user_org = Organisation(orgId=org_id, name=f"{first_name}'s Organisation", description=f"This is {last_name} {first_name}'s organisation", userId=user_id)
        db.session.add(user_org)
        db.session.commit()

        payload = {
            "status": "success",
            "message": "Registration successful",
            "data": {
                "accessToken": str(access_token),
                "user": {
                    "userId": user_id,
                    "firstName": first_name,
                    "lastName": last_name,
                    "email": email,
                    "phone": phone
                }
            }
        }

        response = make_response(payload)
        response.set_cookie('X-access-token', value=access_token, expires=datetime.now() + timedelta(minutes=3), secure=True, httponly=True, samesite='Strict')

        return response, 201
    except Exception as e:
        return jsonify({
            "status": "Internal Server Error",
            "message": "Registration unsuccessful",
            "statusCode": 500,
            "error": str(e)
        }), 500
    
@auth.route('/login', methods=['POST'])
def login():
    request_data = request.get_json()
    email = request_data['email']
    password = request_data['password']

    user = User.query.filter_by(email=email).first()
    is_password_correct = check_password(password, user)

    if not email or not password or not user:
        return jsonify({
            "status": "Bad request",
            "message": "Authentication failed",
            "statusCode": 401
        }), 401
    elif is_password_correct == False:
        return jsonify({
            "status": "Bad request",
            "message": "Authentication failed",
            "statusCode": 401
        }), 401
    
    data = {
        "id": user.id,
        "exp": datetime.now() + timedelta(minutes=3)
    }
    access_token = generate_access_token(data)

    payload = {
        "status": "success",
        "message": "Login successful",
        "data": {
            "accessToken": str(access_token),
            "user": {
                "userId": user.id,
                "firstName": user.firstName,
                "lastName": user.lastName,
                "email": email,
                "phone": user.phone
            }
        }
    }

    response = make_response(jsonify(payload))
    response.set_cookie('X-access-token', value=access_token, expires=datetime.now() + timedelta(minutes=3), secure=True, httponly=True, samesite='Strict')

    return response, 200