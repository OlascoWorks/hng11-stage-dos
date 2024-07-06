from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os, uuid

load_dotenv()
db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URL', 'sqlite:///database.db') 
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    app.config.from_pyfile('config.py')

    db.init_app(app)

    from .controllers import token_required
    from .models import Organisation, User, UserOrganisation
    @app.route('/api/users/<user_id>')
    @token_required
    def get_user(currentUser, access_token, user_id):
        if currentUser == None:
            return jsonify({
                "status": "unsuccessful",
                "message": "user not logged in"
            }), 401
        
        payload = {}
        user = currentUser
        if currentUser.userId != user_id:
            orgs_user1 = db.session.query(UserOrganisation.orgId).filter_by(userId=currentUser.userId).subquery()
            common_orgs = db.session.query(UserOrganisation).filter(UserOrganisation.userId == user_id, UserOrganisation.orgId.in_(orgs_user1)).all()

            if not common_orgs:
                return jsonify({
                    "status": "unsuccessful",
                    "message": "user does not have access to this resource"
                }), 403
       
        user = User.query.filter_by(userId=user_id).first()
        if not user:
            return jsonify({
                "status": "unsuccessful",
                "message": "user does not exist"
            }), 403
        
        return jsonify({
            "status": "success",
            "message": "here is your info",
            "data": {
                "userId": user.userId,
                "firstName": user.firstName,
                "lastName": user.lastName,
                "email": user.email,
                "phone": user.phone
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
            request_data = request.get_json()
            name = request_data['name']
            description = request_data['description']

            if not name or len(name) < 0:
                return jsonify({
                    "status": "Bad Request",
                    "message": "Client error",
                    "statusCode": 400
                }), 400
            
            org_id = uuid.uuid4().hex
            new_org = Organisation(orgId=str(org_id), name=name, description=description, userId=currentUser.userId)
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
            organisations = Organisation.query.filter_by(userId=currentUser.userId).all()
            orgs = []
            for organisation in organisations:
                orgs.append({
                    "orgId": organisation.orgId,
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
        org = UserOrganisation.query.filter_by(orgId=orgId, userId=currentUser.userId).first()

        if not organisation:
            return jsonify({
                "status": "unsuccessful",
                "message": "organisation does not exist"
            }), 403
        elif not org:
            return jsonify({
                "status": "unsuccessful",
                "message": "user does not have access to this resource"
            }), 403
        
        return jsonify({
            "status": "success",
            "message": "here is the organisation",
            "data": {
                "orgId": organisation.orgId,
                "name": organisation.name,
                "description": organisation.description
            }
        }), 200

    @app.route('/api/organisations/<orgId>/users', methods=['POST'])
    def add_user_to_org(orgId):
        organisation = Organisation.query.filter_by(orgId=orgId).first()
        user_id = request.get_json()['userId']
        user = User.query.filter_by(userId=user_id).first()
        org = UserOrganisation.query.filter_by(orgId=orgId, userId=user_id).first()

        if not organisation:
            return jsonify({
                "status": "unsuccessful",
                "message": "organisation does not exist"
            }), 401
        elif not user:
            return jsonify({
                "status": "unsuccessful",
                "message": "user with provided id does not exist"
            }), 401
        elif org:
            return jsonify({
                "status": "unsuccessful",
                "message": "user already exists in this organisation"
            }), 401
        
        new_user_to_org = UserOrganisation(orgId=orgId, userId=user_id)
        db.session.add(new_user_to_org)
        db.session.commit()
        
        return jsonify({
            "status": "success",
            "message": "User added to organisation successfully",
        }), 200

    from .auth import auth
    app.register_blueprint(auth, url_prefix='/auth')

    with app.app_context():
        db.create_all()

    return app