from flask import Blueprint, request, jsonify, make_response
from .models import User, Organisation, UserOrganisation
from .controllers import validate_fields, generate_access_token, check_password
from datetime import datetime, timedelta
import bcrypt, uuid

auth = Blueprint('auth', __name__)
from api import db

@auth.route('/register', methods=['POST'])
def register():
    try:
        request_data = request.get_json(silent=True)
        first_name = request_data['firstName']
        last_name = request_data['lastName']
        email = request_data['email']
        password = request_data['password']
        phone = request_data['phone'] if 'phone' in request_data else ''

        if not first_name or not last_name or not email:
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
            "exp": datetime.now() + timedelta(minutes=15)
        }

        pw_hash = hashed_password.decode('utf-8')
        new_user = User(userId=user_id, firstName=first_name, lastName=last_name, email=email, password=pw_hash, phone=phone)
        db.session.add(new_user)
        db.session.commit()

        access_token = generate_access_token(data)
        
        org_id = str(uuid.uuid4().hex)
        user_org = Organisation(orgId=org_id, name=f"{first_name}'s Organisation", description=f"This is {last_name} {first_name}'s organisation", userId=user_id)
        db.session.add(user_org)
        db.session.commit()

        user_organisation = UserOrganisation(userId=user_id, orgId=org_id)
        db.session.add(user_organisation)
        db.session.commit()

        return jsonify({
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
        }), 201
    except Exception as e:
        return jsonify({
                "status": "Bad request",
                "message": "Registration unsuccessful",
                "statusCode": 422
            }), 422
    
@auth.route('/login', methods=['POST'])
def login():
    request_data = request.get_json()
    email = request_data['email']
    password = request_data['password']

    user = User.query.filter_by(email=email).first()

    payload = {
        "status": "Bad request",
        "message": "Authentication failed",
        "statusCode": 401
    } 
    if not email or not password or not user:  return jsonify(payload), 401
    elif not check_password(password, user.password):  return jsonify(payload), 401
    
    data = {
        "id": user.userId,
        "exp": datetime.now() + timedelta(minutes=15)
    }
    access_token = generate_access_token(data)

    return jsonify({
        "status": "success",
        "message": "Login successful",
        "data": {
            "accessToken": str(access_token),
            "user": {
                "userId": user.userId,
                "firstName": user.firstName,
                "lastName": user.lastName,
                "email": email,
                "phone": user.phone
            }
        }
    }), 200