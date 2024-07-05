from .main import db

class User(db.Model):
    userId = db.Column(db.String(80), primary_key=True, unique=True)
    firstName = db.Column(db.String(60), nullable=False)
    lastName = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    phone = db.Column(db.String(80))

    def __repr__(self) -> str:
        return f"This is User - {self.lastName} {self.firstName} with id - {self.userId}"

class Organisation(db.Model):
    orgId = db.Column(db.String(80), primary_key=True, unique=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(600))
    user_id = db.Column(db.String(80))

    def __repr__(self) -> str:
        return f"This is organisation {self.name} belonging to"