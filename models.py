from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from decimal import Decimal

db = SQLAlchemy()

class User(db.Model, UserMixin):
    """
    User model to store user registration details, authentication information,
    and cryptocurrency wallet details.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    account_number = db.Column(db.String(20), unique=True, nullable=False)
    solana_public = db.Column(db.String(100), unique=True, nullable=True)
    # In a real application, solana_private should be encrypted or not stored directly.
    solana_private = db.Column(db.String(200), nullable=True)
    sol_balance = db.Column(db.Numeric(20, 8), default=Decimal('0.00'))
    usdc_balance = db.Column(db.Numeric(20, 8), default=Decimal('0.00'))
    usdc_public = db.Column(db.String(100), unique=True, nullable=True)
    # In a real application, mimephrase (seed phrase) should be encrypted or not stored directly.
    mimephrase = db.Column(db.String(200), nullable=True)
    mimephrase_validated = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    accounts = db.relationship('Account', backref='user', lazy=True)
    activities = db.relationship('UserActivity', backref='user', lazy=True)
    sent_transactions = db.relationship('Transaction', foreign_keys='Transaction.sender_id', backref='sender', lazy=True)
    received_transactions = db.relationship('Transaction', foreign_keys='Transaction.receiver_id', backref='receiver', lazy=True)
    help_requests = db.relationship('Help', backref='user', lazy=True)

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"

class Help(db.Model):
    """
    Help model to store user-reported issues and help requests.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    issue_type = db.Column(db.String(50), nullable=False)
    other_issue = db.Column(db.Text, nullable=True)
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='Open') # e.g., 'Open', 'In Progress', 'Closed'

    def __repr__(self):
        return f"<Help {self.id} - User: {self.user_id} - Type: {self.issue_type}>"

class Contact(db.Model):
    """
    Contact model to store messages submitted via the contact form.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(255), nullable=True) # Added based on HTML form
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Contact {self.id} - {self.email}>"

class UserActivity(db.Model):
    """
    UserActivity model to log various user actions within the application.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity_type = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True) # IPv4 or IPv6
    user_agent = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<UserActivity {self.id} - User: {self.user_id} - Type: {self.activity_type}>"

class Transaction(db.Model):
    """
    Transaction model to record all financial transactions.
    """
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Nullable for external transfers
    receiver_address = db.Column(db.String(255), nullable=True) # For external crypto/bank addresses
    amount = db.Column(db.Numeric(20, 8), nullable=False)
    currency = db.Column(db.String(10), nullable=False)
    fee = db.Column(db.Numeric(20, 8), default=Decimal('0.00'))
    net_received = db.Column(db.Numeric(20, 8), nullable=True) # Amount received by recipient after fees
    transaction_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False) # e.g., 'Pending', 'Completed', 'Failed'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    transaction_hash = db.Column(db.String(255), nullable=True) # For blockchain transaction IDs
    paystack_reference = db.Column(db.String(255), nullable=True) # For Paystack transaction references
    notes = db.Column(db.Text, nullable=True) # For conversion details, transfer reasons, etc.
    external_account_name = db.Column(db.String(255), nullable=True) # For external bank transfers
    external_bank_name = db.Column(db.String(255), nullable=True) # For external bank transfers

    def __repr__(self):
        return f"<Transaction {self.id} - {self.transaction_type} {self.amount} {self.currency}>"

class Account(db.Model):
    """
    Account model to represent different bank accounts a user can hold.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    account_type = db.Column(db.String(50), nullable=False) # e.g., 'Savings Account', 'Current Account', 'Domiciliary Account'
    balance = db.Column(db.Numeric(20, 2), default=Decimal('0.00'))
    max_balance = db.Column(db.String(50), nullable=True) # Stores string like '₦5,000,000' or 'Unlimited'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"<Account {self.id} - {self.account_type} for User {self.user_id}>"
