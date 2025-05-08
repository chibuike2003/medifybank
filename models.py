from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    naira_balance = db.Column(db.Float, default=0.0)
    usd_balance = db.Column(db.Float, default=0.0)

    account_number = db.Column(db.String(10), unique=True, nullable=False)
    solana_public = db.Column(db.String(100), nullable=False)
    solana_private = db.Column(db.String(200), nullable=False)
    mimephrase = db.Column(db.String(100), unique=True)
    mimephrase_validated = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)




class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Numeric(precision=18, scale=4))
    fee = db.Column(db.Numeric(precision=18, scale=4))
    net_received = db.Column(db.Numeric(precision=18, scale=4))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Optional: Relationships for easy access
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_transactions')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_transactions')
