from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import os, uuid

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') if os.environ.get('DATABASE_URL') else 'sqlite:///database.db'
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    app.config.from_pyfile('config.py')

    db.init_app(app)

    from .controllers import token_required
    from .models import Organisation
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

    @app.route('/api/organisations', methods=['GET', 'POST'])
    @token_required
    def orgs(currentUser, access_token):
        if currentUser == None:
            return jsonify({
                "status": "unsuccessful",
                "message": "user not logged in"
            }), 401
        
        if request.method == 'POST':
            name = request.form.get('name')
            description = request.form.get('description')

            if not name or len(name) < 0:
                return jsonify({
                    "status": "Bad Request",
                    "message": "Client error",
                    "statusCode": 400
                }), 400
            
            org_id = uuid.uuid4.hex()
            new_org = Organisation(orgId=str(org_id), name=name, description=description, userId=currentUser.id)
            db.session.add(new_org)
            db.session.commit()

            return jsonify({
                "status": "success",
                "message": "Organisation created successfully",
                "data": {
                    "orgId": str(org_id), 
                    "name": name, 
                    "description": description
                }
            })
        else:
            organisations = Organisation.query.filter_by(userId=currentUser.id).all()
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

    @app.route('/api/organisations/<orgId>')
    @token_required
    def add_org(currentUser, access_token, orgId):
        if currentUser == None:
            return jsonify({
                "status": "unsuccessful",
                "message": "user not logged in"
            }), 401
        
        organisation = Organisation.query.filter_by(orgId=orgId).first()

        if not organisation:
            return jsonify({
                "status": "unsuccessful",
                "message": "organisation does not exist"
            }), 403
        elif organisation.userId not in currentUser.userId.strip():
            return jsonify({
                "status": "unsuccessful",
                "message": "user does not have access to this resource"
            }), 403
        
        return jsonify({
            "status": "success",
            "message": "here is the organisation",
            "data": {
                "orgId": organisation.id,
                "name": organisation.name,
                "description": organisation.description
            }
        }), 200

    @app.route('/api/organisations/<orgId>/users', methods=['POST'])
    def add_user_to_org(currentUser, access_token, orgId):
        organisation = Organisation.query.filter_by(orgId=orgId).first()

        if not organisation:
            return jsonify({
                "status": "unsuccessful",
                "message": "organisation does not exist"
            }), 401
        
        user_id = request.form.get('userId')
        if user_id in organisation.userId.strip():
            return jsonify({
                "status": "unsuccessful",
                "message": "user already exists in this organisation"
            }), 401
        
        organisation.userId += f" {user_id}"
        
        return jsonify({
            "status": "success",
            "message": "User added to organisation successfully",
        }), 200

    from .auth import auth
    app.register_blueprint(auth, url_prefix='/auth')

    with app.app_context():
        db.create_all()

    return app