from api import db

class User(db.Model):
    userId = db.Column(db.String(80), primary_key=True, unique=True)
    firstName = db.Column(db.String(60), nullable=False)
    lastName = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    phone = db.Column(db.String(80))

    def __repr__(self) -> str:
        return f"This is User - {self.lastName} {self.firstName} with id - {self.userId}"

class Organisation(db.Model):
    orgId = db.Column(db.String(80), primary_key=True, unique=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(600))
    userId = db.Column(db.String(80))

    def __repr__(self) -> str:
        return f"This is organisation {self.name}"

class UserOrganisation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.String(80), db.ForeignKey('user.userId'), nullable=False)
    orgId = db.Column(db.String(80), db.ForeignKey('organisation.orgId'), nullable=False)

    user = db.relationship('User', backref=db.backref('user_organisations', cascade="all, delete-orphan"))
    organisation = db.relationship('Organisation', backref=db.backref('user_organisations', cascade="all, delete-orphan"))

    def __repr__(self) -> str:
        return f"User {self.userId} is part of Organisation {self.orgId}"