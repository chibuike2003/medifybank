from flask import Flask, render_template, redirect, url_for, flash, request,send_file,jsonify,Blueprint,session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from dotenv import load_dotenv
from utils import generate_unique_account_number, generate_solana_wallet, generate_mnemonic,generate_unique_mimephrase, generate_solana_wallet, get_solana_balance
from decimal import Decimal


import os

import qrcode
from io import BytesIO

# Route 
from models import db, User
from forms import SignupForm, LoginForm

bp = Blueprint('bank', __name__)

app = Flask(__name__)
load_dotenv()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///medifybankwallet.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def is_valid_solana_address(address):
    """Validate Solana wallet format (Base58, length 32-44)"""
    base58_pattern = r'^[1-9A-HJ-NP-Za-km-z]{32,44}$'
    return re.match(base58_pattern, address)

def is_possible_sui_address(address):
    """Detect Sui address format: 0x + 64 hex characters"""
    return re.match(r'^0x[a-fA-F0-9]{64}$', address)

@app.route('/home', methods=['GET', 'POST'])
def index():
        return render_template('index.html',)






@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm')

        # Basic validation
        if not username or not email or not password or not confirm:
            flash('All fields are required', 'danger')
        elif password != confirm:
            flash('Passwords do not match', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
        else:
            # Generate account and Solana keys
            from utils import generate_unique_account_number, generate_solana_wallet
            account_number = generate_unique_account_number()
            solana_public, solana_private = generate_solana_wallet()

            mimephrase = generate_unique_mimephrase()

            new_user = User(
                username=username,
                email=email,
                account_number=account_number,
                solana_public=solana_public,
                solana_private=solana_private,
                mimephrase=mimephrase
            )
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully. You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)  # Make sure user has UserMixin and login_user is imported
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    sol_balance = get_solana_balance(current_user.solana_public)
    return render_template('dashboard.html', user=current_user, sol_balance=sol_balance)



@app.route('/add_funds', methods=['GET', 'POST'])
@login_required
def add_funds():
    if request.method == 'POST':
        action = request.form.get('action')

        # Example: Transfer Funds
        if action == 'transfer':
            recipient_account = request.form.get('recipient_account')
            amount = float(request.form.get('amount'))
            if transfer_funds(current_user, recipient_account, amount):
                flash(f"Successfully transferred {amount} to {recipient_account}.", 'success')
            else:
                flash("Failed to transfer funds. Check recipient details and balance.", 'danger')

        # Example: Pay Bills
        elif action == 'pay_bills':
            bill_type = request.form.get('bill_type')
            bill_amount = float(request.form.get('bill_amount'))
            if pay_bills(current_user, bill_type, bill_amount):
                flash(f"Successfully paid {bill_type} bill of {bill_amount}.", 'success')
            else:
                flash("Failed to pay bill. Insufficient balance.", 'danger')

        # Example: Buy Airtime
        elif action == 'buy_airtime':
            amount = float(request.form.get('airtime_amount'))
            phone_number = request.form.get('phone_number')
            if buy_airtime(current_user, phone_number, amount):
                flash(f"Successfully bought {amount} airtime for {phone_number}.", 'success')
            else:
                flash("Failed to buy airtime. Check balance and details.", 'danger')

        # Example: Buy Data
        elif action == 'buy_data':
            data_plan = request.form.get('data_plan')
            data_amount = float(request.form.get('data_amount'))
            if buy_data(current_user, data_plan, data_amount):
                flash(f"Successfully bought {data_amount} data for {data_plan}.", 'success')
            else:
                flash("Failed to buy data. Check balance and plan details.", 'danger')

        return redirect(url_for('add_funds'))

    return render_template('add_funds.html', user=current_user)

@app.route('/validate_mimephrase', methods=['GET', 'POST'])
@login_required
def validate_mimephrase():
    if current_user.mimephrase_validated:
        flash("You have already validated your mimephrase.", "info")
        return redirect(url_for('send_sol'))  # Redirect to send SOL page if already validated

    if request.method == 'POST':
        mimephrase = request.form.get('mimephrase').strip()

        # Fetch the user based on the current logged-in user's id and mimephrase
        user = User.query.filter_by(id=current_user.id, mimephrase=mimephrase).first()

        if user:
            # Update the user record to mark mimephrase as validated
            user.mimephrase_validated = True
            db.session.commit()

            flash(f'Mimephrase is valid. Welcome, {user.username}!', 'success')
            return redirect(url_for('send_sol'))  # Redirect to send SOL page
        else:
            flash('Invalid mimephrase. Please try again.', 'danger')
            return redirect(url_for('validate_mimephrase'))  # Reload the validation page

    return render_template('mimephrase_validator.html')


@app.route('/reveal_mimephrase', methods=['GET', 'POST'])
@login_required
def reveal_mimephrase():
    password = request.form['password']
    user = get_current_user()  # Fetch the logged-in user
    if user.validate_password(password):  # Check the password
        return jsonify({
            'mimephrase': user.mimephrase,  # Return the mimephrase
            'validated': True  # Flag to indicate successful validation
        })
    else:
        return jsonify({'error': 'Incorrect password'})



# You might need a method to validate Solana addresses
def is_valid_solana_address(address):
    # This function should check if the address follows the Solana address format
    # For simplicity, assume a basic check here.
    return len(address) == 44  # Example: Solana addresses are 44 characters long

@app.route('/send-sol', methods=['GET', 'POST'])
@login_required
def send_sol():
    if not current_user.mimephrase_validated:
        flash("You must validate your mimephrase before sending SOL.", "warning")
        return redirect(url_for('validate_mimephrase'))  # Redirect to mimephrase validation if not validated

    if request.method == 'POST':
        recipient_wallet = request.form['recipient'].strip()
        amount = Decimal(request.form['amount'])

        # 1. Check if the user is sending to themselves
        if recipient_wallet == current_user.solana_public:
            flash("You cannot send SOL to yourself.", "danger")
            return redirect(request.url)

        # 2. Check if the wallet address is a valid Solana address
        if not is_valid_solana_address(recipient_wallet):
            flash("This isn't a valid Solana wallet address.", "danger")
            return redirect(request.url)

        # 3. Check if the user has sufficient balance
        if current_user.sol_balance < amount:
            flash("Your balance is low. You don't have enough SOL.", "danger")
            return redirect(request.url)

        # Deduct amount and send SOL to recipient (update balance, etc.)
        sender = current_user
        recipient = User.query.filter_by(solana_public=recipient_wallet).first()

        if not recipient:
            flash("Recipient wallet not found.", "danger")
            return redirect(request.url)

        fee = amount * Decimal('0.01')  # 1% fee
        net_amount = amount - fee

        sender.sol_balance -= amount  # Deduct from sender
        recipient.sol_balance += net_amount  # Add to recipient

        # Log the transaction
        tx = Transaction(
            sender_id=sender.id,
            recipient_id=recipient.id,
            amount=amount,
            fee=fee,
            net_received=net_amount
        )
        db.session.add(tx)
        db.session.commit()

        flash(f"Successfully sent {net_amount:.4f} SOL to {recipient.username}. 1% fee applied.", "success")
        return redirect('/dashboard')  # Redirect to dashboard or success page

    return render_template('sendsol.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')

    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
