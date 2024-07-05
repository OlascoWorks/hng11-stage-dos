from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from .auth import auth
from .controllers import token_required
from .models import Organisation
import os, uuid

db = SQLAlchemy()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') if os.environ.get('DATABASE_URL') else 'sqlite:///database.db'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config.from_pyfile('config.py')

db.init_app(app)

@app.route('/api/users/<user_id>')
@token_required
def get_user(currentUser, access_token, user_id):
    if currentUser == None:
        return jsonify({
            "status": "unsuccessful",
            "message": "user not logged in"
        }), 401
    
    user = currentUser
    if currentUser.id != user_id:
        return jsonify({
            "status": "unsuccessful",
            "message": "user does not have access to this resource"
        }), 403
    
    return jsonify({
        "status": "success",
        "message": "here is your info",
        "data": {
            "userId": currentUser.id,
            "firstName": currentUser.firstName,
            "lastName": currentUser.lastName,
            "email": currentUser.email,
            "phone": currentUser.phone
        }
    }), 200

@app.route('/api/organisations')
@token_required
def get_user(currentUser, access_token):
    if currentUser == None:
        return jsonify({
            "status": "unsuccessful",
            "message": "user not logged in"
        }), 401
    
    organisations = Organisation.query.filter_by(userId=currentUser.id).first()
    orgs = []
    for organisation in organisations:
        orgs.append({
            "orgId": organisation.id,
            "name": organisation.name,
            "description": organisation.description
        })
    
    return jsonify({
        "status": "success",
        "message": "here are your organisations",
        "data": {
            "organisations": orgs
        }
    }), 200

app.register_blueprint(auth, url_prefix='/auth')

if __name__ == '__main__':
    app.run()