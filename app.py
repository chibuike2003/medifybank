import requests
import json
from decimal import Decimal
import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
from datetime import datetime
import pytz
import re
from sqlalchemy import or_
import base64 # For QR code generation
import io # For QR code generation
import qrcode # For QR code generation
import random # Ensure random is imported at the top for clarity
from werkzeug.security import generate_password_hash, check_password_hash # Import these

# Assuming these are defined in your models.py
from models import db, User, Help, Contact, UserActivity, Transaction, Account # Ensure Transaction and Account are imported

# Assuming these are defined in your forms.py
# from forms import SignupForm, LoginForm

# Word list for generating mimephrase (from your provided code)
word_list = [
"sun", "moon", "star", "light", "dark", "sky", "earth", "fire", "ocean", "wind", "cloud", "tree", "stone", "river", "dream", "storm", "shadow", "spark", "voice", "echo",
"wave", "mountain", "valley", "sea", "sand", "forest", "hill", "lake", "night", "day", "life", "death", "birth", "growth", "decay", "hope", "fear", "joy", "sorrow",
"path", "journey", "destination", "home", "family", "friend", "love", "hate", "peace", "war", "calm", "chaos", "serenity", "turmoil", "beauty", "ugliness", "truth", "lie",
"memory", "forgetfulness", "past", "present", "future", "time", "space", "matter", "energy", "body", "mind", "spirit", "soul", "heart", "brain", "thought", "emotion", "action",
"flower", "bird", "fish", "animal", "insect", "plant", "fruit", "vegetable", "mineral", "rock", "soil", "water", "air", "earthquake", "volcano", "tornado", "hurricane", "tsunami",
"laughter", "tears", "smile", "frown", "song", "dance", "music", "art", "poetry", "story", "history", "culture", "tradition", "community", "society", "civilization",
"atom", "molecule", "cell", "organism", "ecosystem", "universe", "galaxy", "starlight", "blackhole", "comet", "meteor", "asteroid", "planet", "moonlight", "solarflare",
"computer", "software", "hardware", "algorithm", "data", "information", "knowledge", "wisdom", "intelligence", "artificial", "machine", "learning", "neural", "network",
"city", "town", "village", "country", "nation", "state", "province", "district", "neighborhood", "street", "avenue", "road", "highway", "freeway", "bridge", "tunnel",
"car", "truck", "bus", "train", "plane", "boat", "ship", "bicycle", "motorcycle", "scooter", "skateboard", "wheelchair", "spaceship", "rocket", "satellite", "drone"
]

# ✅ Generate a unique 15-word mimephrase (from your provided code)
def generate_unique_mimephrase():
    while True:
        phrase = "-".join(random.sample(word_list, 15))  # 15 unique random words
        existing = User.query.filter_by(mimephrase=phrase).first()
        if not existing:
            return phrase

# ✅ Generate a 12-word mnemonic (seed) phrase (from your provided code)
# Note: This function requires the 'mnemonic' library, which is not standard.
# If you intend to use it, ensure 'pip install mnemonic' is done.
# For now, it's commented out to prevent import errors if not installed.
# from mnemonic import Mnemonic
def generate_mnemonic():
    # mnemo = Mnemonic("english")
    # return mnemo.generate(strength=128)  # 12 words
    return "mock mnemonic phrase for testing purposes"


# ✅ Generate unique 10-digit account number (from your provided code)
def generate_unique_account_number():
    while True:
        account_number = ''.join([str(random.randint(0, 9)) for _ in range(10)])
        existing = User.query.filter_by(account_number=account_number).first()
        if not existing:
            return account_number

# ✅ Generate Solana wallet (public & base58 private key) (from your provided code)
def generate_solana_wallet():
    # Mock implementation, replace with actual solana.keypair logic
    # from solana.keypair import Keypair
    # keypair = Keypair()
    # public_key = str(keypair.public_key)
    # private_key = b58encode(keypair.secret_key).decode('utf-8')
    # return public_key, private_key
    return f"SOLPUB{os.urandom(16).hex()}", f"SOLPRIV{os.urandom(32).hex()}"

# ✅ Get Solana balance using public key (from your provided code)
def get_solana_balance(pubkey):
    # Mock implementation, replace with actual Solana RPC client
    # from solana.rpc.api import Client
    # client = Client(os.getenv("SOLANA_RPC"))
    # try:
    #     response = client.get_balance(pubana_public)
    #     lamports = response['result']['value']
    #     return Decimal(lamports / 1e9)  # Convert from lamports to SOL
    # except Exception as e:
    #     print("Error getting balance:", e)
    #     return Decimal('0.0')
    print(f"Mock: Getting Solana balance for {pubkey}")
    return Decimal(f"{random.uniform(0.01, 5.0):.4f}")

def generate_usdc_wallet_address():
    """Mocks USDC (EVM) wallet address generation."""
    return f"0x{os.urandom(20).hex()}" # Standard Ethereum address format

LOCAL_TIMEZONE = pytz.timezone('Africa/Lagos')

# Flask App setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a_very_secret_key_that_should_be_in_env')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///globalpay.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Enable Jinja2 'do' extension
app.jinja_env.add_extension('jinja2.ext.do')


# Configure logging
import logging
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_activity(user_id, activity_type):
    """Logs user activity with timestamp, IP address, and user agent."""
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    new_activity = UserActivity(user_id=user_id, activity_type=activity_type,
                                 ip_address=ip_address, user_agent=user_agent)
    db.session.add(new_activity)
    db.session.commit()

ACCOUNT_DETAILS = {
    "Savings Account": {
        "conditions": "• No monthly maintenance fee\n• Minimum opening balance: ₦1,000\n• Interest earning",
        "max_balance": "₦5,000,000"
    },
    "Current Account": {
        "conditions": "• Monthly maintenance fee applies\n• Minimum opening balance: ₦5,000\n• Chequebook issued",
        "max_balance": "Unlimited"
    },
    "Fixed Deposit Account": {
        "conditions": "• Minimum deposit: ₦100,000\n• Fixed tenure\n• Higher interest rate",
        "max_balance": "₦100,000,000"
    },
    "Joint Account": {
        "conditions": "• Operated by two or more persons\n• Requires mandate (either/all signatories)",
        "max_balance": "₦10,000,000"
    },
    "Corporate Account": {
        "conditions": "• Requires CAC documents\n• Minimum opening balance: ₦10,000\n• Business transaction features",
        "max_balance": "Unlimited"
    },
    "Student Account": {
        "conditions": "• Age: 16-30 years\n• No maintenance fees\n• Requires student ID",
        "max_balance": "₦300,000"
    },
    "Domiciliary Account": {
        "conditions": "• Operates in USD/GBP/EUR\n• International transfers enabled\n• Valid ID and utility bill required",
        "max_balance": "$10,000 or equivalent"
    }
}

# --- API Configuration (Add these to your settings or .env file) ---
COINGECKO_API_BASE_URL = os.getenv('COINGECKO_API_BASE_URL', 'https://api.coingecko.com/api/v3')
OPENEXCHANGERATES_API_KEY = os.getenv('OPENEXCHANGERATES_API_KEY') # Make sure this is set in your .env
OPENEXCHANGERATES_API_BASE_URL = os.getenv('OPENEXCHANGERATES_API_BASE_URL', 'https://open.er-api.com/v6/latest/')

def get_crypto_price_usd(crypto_id):
    """Fetches the current USD price of a cryptocurrency from CoinGecko."""
    try:
        url = f"{COINGECKO_API_BASE_URL}/simple/price?ids={crypto_id}&vs_currencies=usd"
        response = requests.get(url)
        response.raise_for_status() # Raise an exception for HTTP errors
        data = response.json()
        if data and crypto_id in data and 'usd' in data[crypto_id]:
            return Decimal(str(data[crypto_id]['usd']))
        app.logger.error(f"Error: Could not get USD price for {crypto_id} from CoinGecko. Data: {data}")
        return None
    except requests.exceptions.RequestException as e:
        app.logger.error(f"API call to CoinGecko failed: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Error parsing CoinGecko response: {e}")
        return None

def get_fiat_exchange_rate(from_fiat, to_fiat):
    """Fetches fiat-to-fiat exchange rates using Open Exchange Rates API (or similar)."""
    if not OPENEXCHANGERATES_API_KEY:
        app.logger.warning("Warning: OPENEXCHANGERATES_API_KEY is not set. Cannot fetch real fiat rates.")
        return None

    try:
        url = f"{OPENEXCHANGERATES_API_BASE_URL}{from_fiat.upper()}"
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        if data and data['result'] == 'success' and to_fiat.upper() in data['rates']:
            return Decimal(str(data['rates'][to_fiat.upper()]))
        app.logger.error(f"Error: Could not get {from_fiat}-{to_fiat} fiat rate. Data: {data}")
        return None
    except requests.exceptions.RequestException as e:
        app.logger.error(f"API call to Open Exchange Rates failed: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Error parsing Open Exchange Rates response: {e}")
        return None

def get_exchange_rate(from_currency, to_currency):
    """
    Traces the market to get current exchange rates using external APIs.
    Supports NGN, USD, SOL, USDC, BTC, ETH.
    """
    from_currency = from_currency.upper()
    to_currency = to_currency.upper()

    # Define CoinGecko IDs for supported cryptocurrencies
    crypto_ids = {
        'SOL': 'solana',
        'USDC': 'usd-coin',
        'BTC': 'bitcoin',
        'ETH': 'ethereum'
    }

    # --- Direct Fiat-to-Fiat ---
    if from_currency in ['NGN', 'USD'] and to_currency in ['NGN', 'USD']:
        if from_currency == to_currency:
            return Decimal('1.0')
        rate = get_fiat_exchange_rate(from_currency, to_currency)
        if rate:
            app.logger.info(f"Fetched {from_currency} to {to_currency} fiat rate: {rate}")
            return rate
        else:
            app.logger.warning(f"Could not fetch direct fiat rate for {from_currency}/{to_currency}. Attempting via USD.")
            # Fallback to USD if direct is not available or if one is not USD
            if from_currency == 'NGN' and to_currency == 'USD':
                    usd_to_ngn_rate = get_fiat_exchange_rate('USD', 'NGN')
                    if usd_to_ngn_rate and usd_to_ngn_rate > 0:
                        return Decimal('1.0') / usd_to_ngn_rate
            elif from_currency == 'USD' and to_currency == 'NGN':
                    return get_fiat_exchange_rate('USD', 'NGN')


    # --- Crypto to USD ---
    if from_currency in crypto_ids and to_currency == 'USD':
        price = get_crypto_price_usd(crypto_ids[from_currency])
        if price:
            app.logger.info(f"Fetched {from_currency} to USD crypto rate: {price}")
            return price
        return None # Failed to get crypto price

    # --- USD to Crypto ---
    if from_currency == 'USD' and to_currency in crypto_ids:
        price = get_crypto_price_usd(crypto_ids[to_currency])
        if price and price > 0:
            rate = Decimal('1.0') / price
            app.logger.info(f"Calculated USD to {to_currency} crypto rate: {rate}")
            return rate
        return None # Failed to get crypto price

    # --- Crypto to Fiat (via USD) ---
    if from_currency in crypto_ids and to_currency in ['NGN']:
        usd_price = get_crypto_price_usd(crypto_ids[from_currency])
        if usd_price:
            fiat_rate = get_fiat_exchange_rate('USD', to_currency)
            if fiat_rate:
                combined_rate = usd_price * fiat_rate
                app.logger.info(f"Calculated {from_currency} to {to_currency} (via USD) rate: {combined_rate}")
                return combined_rate
        return None

    # --- Fiat to Crypto (via USD) ---
    if from_currency in ['NGN'] and to_currency in crypto_ids:
        fiat_to_usd_rate = get_fiat_exchange_rate(from_currency, 'USD')
        if fiat_to_usd_rate:
            usd_price = get_crypto_price_usd(crypto_ids[to_currency])
            if usd_price and usd_price > 0:
                combined_rate = (Decimal('1.0') / usd_price) * fiat_to_usd_rate
                app.logger.info(f"Calculated {from_currency} to {to_currency} (via USD) rate: {combined_rate}")
                return combined_rate
        return None

    # --- Crypto to Crypto (via USD) ---
    if from_currency in crypto_ids and to_currency in crypto_ids:
        from_usd_price = get_crypto_price_usd(crypto_ids[from_currency])
        to_usd_price = get_crypto_price_usd(crypto_ids[to_currency])
        if from_usd_price and to_usd_price and to_usd_price > 0:
            rate = from_usd_price / to_usd_price
            app.logger.info(f"Calculated {from_currency} to {to_currency} (via USD) rate: {rate}")
            return rate
        return None

    app.logger.warning(f"Unsupported exchange rate request: {from_currency} to {to_currency}")
    return None

def perform_crypto_transfer_mock(sender_public_key, sender_private_key, recipient_address, amount, currency_type):
    """
    Mocks a blockchain transfer. In a real app, this would use web3 libraries
    (e.g., solana-py, web3.py for ERC-20 like USDC) and actual private keys.
    This function *does not* actually send crypto.
    """
    app.logger.info(f"Mocking {currency_type} transfer:")
    app.logger.info(f"  From: {sender_public_key}")
    app.logger.info(f"  To: {recipient_address}")
    app.logger.info(f"  Amount: {amount} {currency_type}")
    # Simulate success
    return {"status": True, "transaction_hash": f"mock_tx_{datetime.now().timestamp()}"}

def perform_internal_crypto_credit(user_id, currency, amount):
    """
    Credits a user's internal crypto balance.
    For SOL, directly updates current_user.sol_balance.
    For USDC, updates usdc_balance field on the User model.
    """
    user = User.query.get(user_id)
    if not user:
        app.logger.error(f"Internal credit failed: User {user_id} not found.")
        return False

    if currency.upper() == 'SOL':
        user.sol_balance += amount
    elif currency.upper() == 'USDC':
        if not hasattr(user, 'usdc_balance'):
            app.logger.error(f"Error: USDC balance not configured for user {user_id}.")
            return False
        user.usdc_balance += amount
    else:
        app.logger.warning(f"Warning: Attempted to internally credit unsupported crypto: {currency} for user {user_id}.")
        return False
    db.session.commit()
    return True

# --- Paystack Configuration ---
PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY')
PAYSTACK_PUBLIC_KEY = os.getenv('PAYSTACK_PUBLIC_KEY') # Not used in this specific transfer flow, but good to have
PAYSTACK_BASE_URL = "https://api.paystack.co"

def paystack_api_call(method, endpoint, data=None, params=None):
    """Helper function to make authenticated calls to Paystack API."""
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    url = f"{PAYSTACK_BASE_URL}{endpoint}"

    try:
        if method == "POST":
            response = requests.post(url, headers=headers, data=json.dumps(data))
        elif method == "GET":
            response = requests.get(url, headers=headers, params=params)
        else:
            raise ValueError("Unsupported HTTP method for Paystack API call.")

        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Paystack API error on {endpoint}: {e} - Response: {getattr(e.response, 'text', 'N/A')}")
        return {"status": False, "message": f"Paystack API error: {e}", "data": None}


def is_valid_solana_address(address):
    """Validate Solana wallet format (Base58, length 32-44)"""
    base58_pattern = r'^[1-9A-HJ-NP-Za-km-z]{32,44}$'
    return re.match(base58_pattern, address)

def is_valid_usdc_address(address):
    """
    Validate USDC address format (standard Ethereum/EVM address)
    0x followed by 40 hexadecimal characters.
    """
    return re.match(r'^0x[a-fA-F0-9]{40}$', address)


def is_possible_sui_address(address):
    """Detect Sui address format: 0x + 64 hex characters"""
    return re.match(r'^0x[a-fA-F0-9]{64}$', address)

@app.route('/home', methods=['GET', 'POST'])
def index():
    return render_template('index.html')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.context_processor
def inject_now():
    def to_local_time(utc_dt):
        if utc_dt is None:
            return ""
        utc_dt = utc_dt.replace(tzinfo=pytz.utc)
        local_dt = utc_dt.astimezone(LOCAL_TIMEZONE)
        return local_dt.strftime('%Y-%m-%d %H:%M:%S')
    return dict(to_local_time=to_local_time, now=datetime.now)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm')

        # Basic validation
        if not username or not email or not password or not confirm_password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('signup'))
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('signup'))
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return redirect(url_for('signup'))

        existing_user_email = User.query.filter_by(email=email).first()
        if existing_user_email:
            flash('Email already registered. Please login or use a different email.', 'danger')
            return redirect(url_for('signup'))

        existing_user_username = User.query.filter_by(username=username).first()
        if existing_user_username:
            flash('Username already taken. Please choose a different username.', 'danger')
            return redirect(url_for('signup'))

        try:
            hashed_password = generate_password_hash(password, method='scrypt')

            # Generate unique account number
            unique_account_number = generate_unique_account_number()

            # Generate Solana wallet
            solana_public_key, solana_private_key = generate_solana_wallet()

            # Generate unique mimephrase
            user_mimephrase = generate_unique_mimephrase()

            new_user = User(
                username=username,
                email=email,
                password_hash=hashed_password,
                account_number=unique_account_number, # Assign the generated account number
                solana_public=solana_public_key,
                solana_private=solana_private_key,
                mimephrase=user_mimephrase,
                mimephrase_validated=False, # Set to False initially
                usdc_public=None # USDC public key will be generated later if needed
            )
            db.session.add(new_user)
            db.session.commit()

            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during signup: {e}', 'danger')
            print(f"Error during signup: {e}") # Log the error for debugging
            return redirect(url_for('signup'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            log_activity(user.id, 'Logged in')
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html')




@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    log_activity(current_user.id, 'Viewed Dashboard')

    # Update Solana balance from mock blockchain
    sol_balance_actual = get_solana_balance(current_user.solana_public)
    if current_user.sol_balance != sol_balance_actual:
        current_user.sol_balance = sol_balance_actual
        db.session.commit()

    # Fetch all bank accounts for the current user (for displaying list)
    user_accounts = Account.query.filter_by(user_id=current_user.id).all()

    # Calculate Naira balance from primary Naira accounts
    naira_account = Account.query.filter_by(user_id=current_user.id).filter(
        (Account.account_type == 'Savings Account') |
        (Account.account_type == 'Current Account')
    ).first()
    # Use sum if a user could hypothetically have multiple (though your create_bank_account prevents this)
    # For robust calculation if multiple accounts might exist, you could do:
    # naira_balance = sum(acc.balance for acc in user_accounts if acc.account_type in ['Savings Account', 'Current Account'])
    naira_balance = naira_account.balance if naira_account else Decimal('0.00')


    # Get USD (Domiciliary) balance
    usd_account = Account.query.filter_by(user_id=current_user.id, account_type='Domiciliary Account').first()
    usd_balance = usd_account.balance if usd_account else Decimal('0.00')

    # Get USDC balance (assuming it's a direct attribute on the User model)
    usdc_balance = current_user.usdc_balance if hasattr(current_user, 'usdc_balance') else Decimal('0.00')

    return render_template(
        'dashboard.html',
        user=current_user,
        sol_balance=current_user.sol_balance, # Already updated above
        naira_balance=naira_balance,
        usd_balance=usd_balance,
        usdc_balance=usdc_balance,
        user_accounts=user_accounts, # Pass the list of all user bank accounts
    )

@app.route('/activity-log')
@login_required
def activity_log():
    log_activity(current_user.id, 'Viewed Activity Log')
    activities = UserActivity.query.filter_by(user_id=current_user.id).order_by(UserActivity.timestamp.desc()).all()
    return render_template('activity_log.html', activities=activities)


@app.route('/report-issue', methods=['GET', 'POST'])
@login_required
def report_issue():
    if request.method == 'POST':
        issue_type = request.form.get('issue_type')
        other_issue = request.form.get('other_issue', '').strip()
        description = request.form.get('description', '').strip()

        if not issue_type:
            flash("Please select an issue type.", "danger")
            return redirect(url_for('report_issue'))
        if not description:
            flash("Please describe the issue.", "danger")
            return redirect(url_for('report_issue'))
        if issue_type == 'other' and not other_issue:
            flash("Please specify your issue in the 'Other' field.", "danger")
            return redirect(url_for('report_issue'))

        new_help = Help(
            user_id=current_user.id,
            issue_type=issue_type,
            other_issue=other_issue if issue_type == 'other' else None,
            description=description,
            timestamp=datetime.utcnow()
        )
        db.session.add(new_help)
        db.session.commit()
        log_activity(current_user.id, f'Reported issue: {issue_type}')
        flash("Your issue has been submitted successfully!", "success")
        return redirect(url_for('report_issue'))

    log_activity(current_user.id, 'Viewed Report Issue page')
    return render_template('help.html', user=current_user)


ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/create-bank-account', methods=['GET', 'POST'])
@login_required
def create_bank_account():
    # Retrieve existing account types for the current user
    existing_account_types = [acc.account_type for acc in current_user.accounts]

    if request.method == 'POST':
        phone = request.form.get('phone')
        account_type = request.form.get('accountType')

        if not phone or not account_type:
            flash("Phone number and account type are required.", "danger")
            log_activity(current_user.id, 'Failed bank account creation: missing fields')
            return render_template(
                "create_bank_account.html",
                existing_account_types=existing_account_types,
                ACCOUNT_DETAILS=ACCOUNT_DETAILS
            )

        if account_type == 'Domiciliary Account':
            existing_dom_account = Account.query.filter_by(user_id=current_user.id, account_type='Domiciliary Account').first()
            if existing_dom_account:
                flash("You already have a Domiciliary Account. Only one is allowed.", "danger")
                log_activity(current_user.id, 'Failed bank account creation: already has Domiciliary Account')
                return render_template(
                    "create_bank_account.html",
                    existing_account_types=existing_account_types,
                    ACCOUNT_DETAILS=ACCOUNT_DETAILS
                )

        if account_type in ['Savings Account', 'Current Account']:
            existing_naira_account = Account.query.filter_by(user_id=current_user.id).filter(
                (Account.account_type == 'Savings Account') |
                (Account.account_type == 'Current Account')
            ).first()
            if existing_naira_account:
                flash("You already have a primary Naira account (Savings/Current).", "danger")
                log_activity(current_user.id, 'Failed bank account creation: already has primary Naira account')
                return render_template(
                    "create_bank_account.html",
                    existing_account_types=existing_account_types,
                    ACCOUNT_DETAILS=ACCOUNT_DETAILS
                )

        account_info = ACCOUNT_DETAILS.get(account_type)
        if not account_info:
            flash("Invalid account type selected.", "danger")
            log_activity(current_user.id, f'Failed bank account creation: invalid account type "{account_type}"')
            return render_template(
                "create_bank_account.html",
                existing_account_types=existing_account_types,
                ACCOUNT_DETAILS=ACCOUNT_DETAILS
            )

        # File validation logic remains the same
        # This part of the code would handle file uploads if implemented.
        # For simplicity in this consolidated app.py, file handling is omitted
        # but the flash messages for missing files are kept as a reminder.
        if account_type == 'Joint Account':
            joint_id_docs = request.files.getlist('joint_id_docs')
            joint_photos = request.files.getlist('joint_photos')
            joint_proof_address = request.files.get('joint_proof_address')

            if not joint_id_docs or any(not allowed_file(f.filename) for f in joint_id_docs if f.filename == ''):
                flash("Please upload valid ID documents (PDF, JPG, PNG) for Joint Account.", "danger")
                return render_template(
                    "create_bank_account.html",
                    existing_account_types=existing_account_types,
                    ACCOUNT_DETAILS=ACCOUNT_DETAILS
                )
            if not joint_photos or any(not allowed_file(f.filename) for f in joint_photos if f.filename == ''):
                flash("Please upload valid passport photos (JPG, PNG) for Joint Account.", "danger")
                return render_template(
                    "create_bank_account.html",
                    existing_account_types=existing_account_types,
                    ACCOUNT_DETAILS=ACCOUNT_DETAILS
                )
            if not joint_proof_address or not allowed_file(joint_proof_address.filename):
                flash("Please upload a valid proof of address (PDF, JPG, PNG) for Joint Account.", "danger")
                return render_template(
                    "create_bank_account.html",
                    existing_account_types=existing_account_types,
                    ACCOUNT_DETAILS=ACCOUNT_DETAILS
                )

        elif account_type == 'Corporate Account':
            incorporation_cert = request.files.get('incorporation_cert')
            moa = request.files.get('moa')
            board_resolution = request.files.get('board_resolution')
            directors_ids = request.files.getlist('directors_ids')
            directors_photos = request.files.getlist('directors_photos')
            business_address = request.files.get('business_address')

            required_files = [incorporation_cert, moa, board_resolution, business_address]
            if any(f is None or (f.filename and not allowed_file(f.filename)) for f in required_files): # Check for empty filename too
                flash("Please upload all required corporate documents as PDF files.", "danger")
                return render_template(
                    "create_bank_account.html",
                    existing_account_types=existing_account_types,
                    ACCOUNT_DETAILS=ACCOUNT_DETAILS
                )
            if not directors_ids or any(not allowed_file(f.filename) for f in directors_ids if f.filename == ''):
                flash("Please upload valid directors' ID documents (PDF, JPG, PNG).", "danger")
                return render_template(
                    "create_bank_account.html",
                    existing_account_types=existing_account_types,
                    ACCOUNT_DETAILS=ACCOUNT_DETAILS
                )
            if not directors_photos or any(not allowed_file(f.filename) for f in directors_photos if f.filename == ''):
                flash("Please upload valid directors' passport photos (JPG, PNG).", "danger")
                return render_template(
                    "create_bank_account.html",
                    existing_account_types=existing_account_types,
                    ACCOUNT_DETAILS=ACCOUNT_DETAILS
                )

        elif account_type == 'Domiciliary Account':
            dom_id_doc = request.files.get('dom_id_doc')
            dom_proof_address = request.files.get('dom_proof_address')
            dom_source_foreign_currency = request.files.get('dom_source_foreign_currency')

            if not dom_id_doc or not allowed_file(dom_id_doc.filename):
                flash("Please upload a valid ID document (PDF, JPG, PNG) for Domiciliary Account.", "danger")
                return render_template(
                    "create_bank_account.html",
                    existing_account_types=existing_account_types,
                    ACCOUNT_DETAILS=ACCOUNT_DETAILS
                )
            if not dom_proof_address or not allowed_file(dom_proof_address.filename):
                flash("Please upload a valid proof of address (PDF, JPG, PNG) for Domiciliary Account.", "danger")
                return render_template(
                    "create_bank_account.html",
                    existing_account_types=existing_account_types,
                    ACCOUNT_DETAILS=ACCOUNT_DETAILS
                )
            if not dom_source_foreign_currency or not allowed_file(dom_source_foreign_currency.filename):
                flash("Please upload a valid source of foreign currency document (PDF) for Domiciliary Account.", "danger")
                return render_template(
                    "create_bank_account.html",
                    existing_account_types=existing_account_types,
                    ACCOUNT_DETAILS=ACCOUNT_DETAILS
                )

        max_balance = account_info['max_balance']

        new_account = Account(
            user_id=current_user.id,
            phone=phone,
            account_type=account_type,
            balance=Decimal('0.00'),
            max_balance=max_balance
        )
        db.session.add(new_account)
        db.session.commit()

        log_activity(current_user.id, f'Created a new bank account: Type={account_type}, Phone={phone}')
        flash(f"{account_type} created successfully!", "success")
        session['permanent_message'] = f"{account_type} account created successfully with max balance {max_balance}"

        return redirect(url_for('dashboard'))

    # This is the GET request rendering, ensure ACCOUNT_DETAILS is passed here too
    return render_template(
        "create_bank_account.html",
        existing_account_types=existing_account_types,
        ACCOUNT_DETAILS=ACCOUNT_DETAILS
    )


@app.route('/add_funds', methods=['GET', 'POST'])
@login_required
def add_funds():
    flash("This functionality is being updated. Please use the new transfer form.", 'info')
    log_activity(current_user.id, 'Viewed old Add Funds functionality.')
    return redirect(url_for('dashboard'))

@app.route('/validate_mimephrase', methods=['GET', 'POST'])
@login_required
def validate_mimephrase():
    if current_user.mimephrase_validated:
        flash("You have already validated your Seed Phrase.", "info")
        log_activity(current_user.id, 'Attempted to validate Seed Phrase (already validated)')
        return redirect(url_for('send_crypto')) # Redirect to new send crypto route

    if request.method == 'POST':
        mimephrase = request.form.get('mimephrase').strip()
        user = User.query.filter_by(id=current_user.id, mimephrase=mimephrase).first()

        if user:
            user.mimephrase_validated = True
            db.session.commit()
            flash(f'Seed Phrase is valid. Welcome, {user.username}!', 'success')
            log_activity(user.id, 'Validated Seed Phrase')
            return redirect(url_for('send_crypto')) # Redirect to new send crypto route
        else:
            flash('Invalid Seed Phrase. Please try again.', 'danger')
            log_activity(current_user.id, 'Failed Seed Phrase validation attempt')
            return redirect(url_for('validate_mimephrase'))

    log_activity(current_user.id, 'Viewed Seed Phrase Validation page')
    return render_template('mimephrase_validator.html')


@app.route('/reveal_mimephrase', methods=['POST'])
@login_required
def reveal_mimephrase():
    password = request.form['password']
    if current_user.check_password(password):
        log_activity(current_user.id, 'Revealed Seed Phrase')
        return jsonify({
            'mimephrase': current_user.mimephrase,
            'validated': True
        })
    else:
        log_activity(current_user.id, 'Failed attempt to reveal Seed Phrase (incorrect password)')
        return jsonify({'error': 'incorrect password'}), 401


@app.route('/account-type')
def account_type():
    # This route now correctly passes ACCOUNT_DETAILS
    return render_template('accounttype.html', ACCOUNT_DETAILS=ACCOUNT_DETAILS)

# --- NEW: Consolidated Crypto Sending Route ---
@app.route('/send-crypto', methods=['GET', 'POST'])
@login_required
def send_crypto():
    if not current_user.mimephrase_validated:
        flash("You must validate your Seed Phrase before sending crypto.", "warning")
        log_activity(current_user.id, 'Redirected to validate Seed Phrase before sending crypto')
        return redirect(url_for('validate_mimephrase'))

    # Check if user has a Domiciliary account
    has_domiciliary_account = Account.query.filter_by(user_id=current_user.id, account_type='Domiciliary Account').first() is not None

    if request.method == 'POST':
        send_currency = request.form.get('send_currency').upper()
        recipient_address_input = request.form.get('recipient_address').strip()
        
        # For external Naira transfers, get bank_code and bank_account_number separately
        bank_code = request.form.get('bank_code')
        bank_account_number = request.form.get('bank_account_number')
        bank_account_name = request.form.get('bank_account_name') # Auto-filled name

        try:
            amount = Decimal(request.form.get('amount'))
            if amount <= 0:
                flash("Amount must be positive.", "danger")
                log_activity(current_user.id, f'Failed {send_currency} send: invalid amount')
                return redirect(url_for('send_crypto'))
            
            # ... (rest of your send_crypto logic) ...
            flash("Send functionality is under development.", "info")
            return redirect(url_for('send_crypto'))

        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            app.logger.error(f"Error in send_crypto: {e}")
            return redirect(url_for('send_crypto'))

    return render_template('send_crypto.html', has_domiciliary_account=has_domiciliary_account)

@app.route('/receive-crypto', methods=['GET'])
@login_required
def receive_crypto():
    solana_address = current_user.solana_public
    usdc_address = current_user.usdc_public if current_user.usdc_public else 'N/A (Generate/Add USDC public key in User model)'

    # Generate QR codes
    sol_qr_b64 = None
    usdc_qr_b64 = None

    if solana_address:
        sol_qr_b64 = generate_qr_code_b64(solana_address)
    if usdc_address and usdc_address != 'N/A (Generate/Add USDC public key in User model)':
        usdc_qr_b64 = generate_qr_code_b64(usdc_address)

    naira_account = Account.query.filter_by(user_id=current_user.id).filter(
        (Account.account_type == 'Savings Account') |
        (Account.account_type == 'Current Account')
    ).first()

    log_activity(current_user.id, 'Viewed Receive Crypto page')
    return render_template('receive_crypto.html',
                           solana_address=solana_address,
                           usdc_address=usdc_address,
                           sol_qr_b64=sol_qr_b64,
                           usdc_qr_b64=usdc_qr_b64,
                           naira_account=naira_account)

def generate_qr_code_b64(data):
    """Generates a QR code for the given data and returns it as a base64 encoded string."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode('utf-8')


@app.route('/buy-solana', methods=['GET', 'POST'])
@login_required
def buy_solana():
    if request.method == 'POST':
        source_currency = request.form.get('source_currency').upper()
        try:
            amount_to_spend = Decimal(request.form.get('amount'))
            if amount_to_spend <= 0:
                flash("Amount must be positive.", "danger")
                return redirect(url_for('buy_solana'))

            # Get user's balance for the source currency
            if source_currency == 'NGN':
                naira_account = Account.query.filter_by(user_id=current_user.id).filter(
                    (Account.account_type == 'Savings Account') |
                    (Account.account_type == 'Current Account')
                ).first()
                if not naira_account or naira_account.balance < amount_to_spend:
                    flash("Insufficient Naira balance.", "danger")
                    return redirect(url_for('buy_solana'))
                source_balance_obj = naira_account
            elif source_currency == 'USDC':
                if not hasattr(current_user, 'usdc_balance') or current_user.usdc_balance < amount_to_spend:
                    flash("Insufficient USDC balance.", "danger")
                    return redirect(url_for('buy_solana'))
                source_balance_obj = current_user # Direct attribute on User model
            else:
                flash("Unsupported source currency.", "danger")
                return redirect(url_for('buy_solana'))

            # Get exchange rate
            exchange_rate = get_exchange_rate(source_currency, 'SOL')
            if not exchange_rate or exchange_rate <= 0:
                flash("Could not get current SOL exchange rate. Please try again later.", "danger")
                return redirect(url_for('buy_solana'))

            sol_to_receive = amount_to_spend * exchange_rate

            # Deduct from source balance
            if source_currency == 'NGN':
                source_balance_obj.balance -= amount_to_spend
            elif source_currency == 'USDC':
                current_user.usdc_balance -= amount_to_spend # Update directly on current_user

            # Add to SOL balance
            current_user.sol_balance += sol_to_receive
            db.session.commit()

            # Log transaction
            new_transaction = Transaction(
                user_id=current_user.id,
                transaction_type='Buy Crypto',
                amount=amount_to_spend,
                currency=source_currency,
                net_received=sol_to_receive,
                net_received_currency='SOL',
                status='Completed',
                notes=f"Bought {sol_to_receive:.4f} SOL with {amount_to_spend:.2f} {source_currency}",
                timestamp=datetime.utcnow()
            )
            db.session.add(new_transaction)
            db.session.commit()

            log_activity(current_user.id, f'Bought {sol_to_receive:.4f} SOL with {amount_to_spend:.2f} {source_currency}')
            flash(f"Successfully bought {sol_to_receive:.4f} SOL!", "success")
            return redirect(url_for('dashboard'))

        except Decimal.InvalidOperation:
            flash("Invalid amount entered.", "danger")
            return redirect(url_for('buy_solana'))
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {e}", "danger")
            app.logger.error(f"Error buying SOL: {e}")
            return redirect(url_for('buy_solana'))

    log_activity(current_user.id, 'Viewed Buy Solana page')
    return render_template('buy_solana.html')


@app.route('/convert-currency', methods=['GET', 'POST'])
@login_required
def convert_currency():
    if request.method == 'POST':
        from_currency = request.form.get('from_currency').upper()
        to_currency = request.form.get('to_currency').upper()
        try:
            amount = Decimal(request.form.get('amount'))
            if amount <= 0:
                flash("Amount must be positive.", "danger")
                return redirect(url_for('convert_currency'))

            if from_currency == to_currency:
                flash("Cannot convert to the same currency.", "danger")
                return redirect(url_for('convert_currency'))

            # Fetch exchange rate
            exchange_rate = get_exchange_rate(from_currency, to_currency)
            if not exchange_rate or exchange_rate <= 0:
                flash("Could not get current exchange rate. Please try again later.", "danger")
                log_activity(current_user.id, f'Failed conversion: no rate for {from_currency} to {to_currency}')
                return redirect(url_for('convert_currency'))

            amount_to_receive = amount * exchange_rate

            # Deduct from 'from_currency' balance
            if from_currency == 'NGN':
                naira_account = Account.query.filter_by(user_id=current_user.id).filter(
                    (Account.account_type == 'Savings Account') | (Account.account_type == 'Current Account')
                ).first()
                if not naira_account or naira_account.balance < amount:
                    flash("Insufficient Naira balance.", "danger")
                    return redirect(url_for('convert_currency'))
                naira_account.balance -= amount
            elif from_currency == 'USD':
                usd_account = Account.query.filter_by(user_id=current_user.id, account_type='Domiciliary Account').first()
                if not usd_account or usd_account.balance < amount:
                    flash("Insufficient USD balance.", "danger")
                    return redirect(url_for('convert_currency'))
                usd_account.balance -= amount
            elif from_currency == 'SOL':
                if current_user.sol_balance < amount:
                    flash("Insufficient SOL balance.", "danger")
                    return redirect(url_for('convert_currency'))
                current_user.sol_balance -= amount
            elif from_currency == 'USDC':
                if not hasattr(current_user, 'usdc_balance'):
                    flash("USDC balance not configured for your account.", "danger")
                    db.session.rollback() # Rollback deduction
                    return redirect(url_for('convert_currency'))
                current_user.usdc_balance += amount_to_receive
            elif from_currency in ['BTC', 'ETH']: # Mock crypto balances
                flash(f"Mock: Deducting {amount} {from_currency}", "info")
                # In a real app, you'd manage mock BTC/ETH balances on the User model
            else:
                flash("Unsupported source currency for conversion.", "danger")
                return redirect(url_for('convert_currency'))

            # Add to 'to_currency' balance
            if to_currency == 'NGN':
                naira_account = Account.query.filter_by(user_id=current_user.id).filter(
                    (Account.account_type == 'Savings Account') | (Account.account_type == 'Current Account')
                ).first()
                if not naira_account:
                    flash("No Naira account to receive funds. Please create one.", "danger")
                    db.session.rollback() # Rollback deduction
                    return redirect(url_for('convert_currency'))
                # Check max balance for Naira account
                max_naira_balance_str = ACCOUNT_DETAILS.get(naira_account.account_type, {}).get('max_balance', 'Unlimited').replace('₦', '').replace(',', '')
                if max_naira_balance_str != 'Unlimited':
                    max_naira_balance = Decimal(max_naira_balance_str)
                    if naira_account.balance + amount_to_receive > max_naira_balance:
                        flash(f"Receiving {to_currency} would exceed your account's maximum balance of {max_naira_balance_str}.", "danger")
                        db.session.rollback()
                        return redirect(url_for('convert_currency'))
                naira_account.balance += amount_to_receive
            elif to_currency == 'USD':
                usd_account = Account.query.filter_by(user_id=current_user.id, account_type='Domiciliary Account').first()
                if not usd_account:
                    flash("No Domiciliary (USD) account to receive funds. Please create one.", "danger")
                    db.session.rollback() # Rollback deduction
                    return redirect(url_for('convert_currency'))
                # Check max balance for Domiciliary account
                max_usd_balance_str = ACCOUNT_DETAILS.get('Domiciliary Account', {}).get('max_balance', 'Unlimited').replace('$', '').replace(',', '').replace(' or equivalent', '')
                if max_usd_balance_str != 'Unlimited':
                    max_usd_balance = Decimal(max_usd_balance_str)
                    if usd_account.balance + amount_to_receive > max_usd_balance:
                        flash(f"Receiving {to_currency} would exceed your account's maximum balance of {max_usd_balance_str}.", "danger")
                        db.session.rollback()
                        return redirect(url_for('convert_currency'))
                usd_account.balance += amount_to_receive
            elif to_currency == 'SOL':
                current_user.sol_balance += amount_to_receive
            elif to_currency == 'USDC':
                if not hasattr(current_user, 'usdc_balance'):
                    flash("USDC balance not configured for your account.", "danger")
                    db.session.rollback() # Rollback deduction
                    return redirect(url_for('convert_currency'))
                current_user.usdc_balance += amount_to_receive
            elif to_currency in ['BTC', 'ETH']: # Mock crypto balances
                flash(f"Mock: Crediting {amount_to_receive} {to_currency}", "info")
                # In a real app, you'd manage mock BTC/ETH balances on the User model
            else:
                flash("Unsupported target currency for conversion.", "danger")
                db.session.rollback() # Rollback deduction
                return redirect(url_for('convert_currency'))

            db.session.commit()

            # Log transaction
            new_transaction = Transaction(
                user_id=current_user.id,
                transaction_type='Currency Conversion',
                amount=amount,
                currency=from_currency,
                net_received=amount_to_receive,
                net_received_currency=to_currency,
                status='Completed',
                notes=f"Converted {amount:.8f} {from_currency} to {amount_to_receive:.8f} {to_currency}",
                timestamp=datetime.utcnow()
            )
            db.session.add(new_transaction)
            db.session.commit()

            log_activity(current_user.id, f'Converted {amount} {from_currency} to {amount_to_receive} {to_currency}')
            flash(f"Successfully converted {amount:.8f} {from_currency} to {amount_to_receive:.8f} {to_currency}", "success")
            return redirect(url_for('dashboard'))

        except Decimal.InvalidOperation:
            flash("Invalid amount entered.", "danger")
            return redirect(url_for('convert_currency'))
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred during conversion: {e}", "danger")
            app.logger.error(f"Error during currency conversion: {e}")
            return redirect(url_for('convert_currency'))

    log_activity(current_user.id, 'Viewed Convert Currency page')
    return render_template('convert_currency.html')

@app.route('/transactions', methods=['GET'])
@login_required
def transactions():
    log_activity(current_user.id, 'Viewed Transactions page')
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).all()
    return render_template('transactions.html', transactions=transactions)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')

        if not name or not email or not subject or not message:
            flash('All fields are required.', 'danger')
            return render_template('contact.html')

        new_contact = Contact(
            name=name,
            email=email,
            subject=subject,
            message=message,
            timestamp=datetime.utcnow()
        )
        db.session.add(new_contact)
        db.session.commit()
        flash('Your message has been sent!', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html')

@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'Logged out')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/get-banks-for-account', methods=['POST'])
@login_required
def get_banks_for_account():
    """
    Mocks an API call to get a list of banks for account resolution.
    In a real application, this would query a financial API (e.g., Paystack, Flutterwave).
    """
    mock_banks = [
        {"name": "Access Bank", "code": "044"},
        {"name": "Guaranty Trust Bank", "code": "058"},
        {"name": "Zenith Bank", "code": "057"},
        {"name": "First Bank of Nigeria", "code": "011"},
        {"name": "United Bank for Africa (UBA)", "code": "033"},
        {"name": "Fidelity Bank", "code": "070"},
        {"name": "Union Bank", "code": "032"},
        {"name": "Ecobank Nigeria", "code": "050"},
        {"name": "Stanbic IBTC Bank", "code": "221"},
        {"name": "Wema Bank", "code": "023"}
    ]
    return jsonify({"success": True, "banks": mock_banks})

@app.route('/verify-bank', methods=['POST'])
@login_required
def verify_bank_account():
    """
    Mocks an API call to verify a bank account number and get the account name.
    In a real application, this would query a financial API (e.g., Paystack, Flutterwave).
    """
    data = request.get_json()
    account_number = data.get('account_number')
    bank_code = data.get('bank_code')

    if not account_number or not bank_code:
        return jsonify({"success": False, "message": "Account number and bank code are required."}), 400

    # Simulate success for specific mock numbers
    if account_number.startswith('123') and bank_code == '058': # GTB
        return jsonify({"success": True, "account_name": "John Doe (Mock GTB)"})
    elif account_number.startswith('987') and bank_code == '044': # Access Bank
        return jsonify({"success": True, "account_name": "Jane Smith (Mock Access)"})
    elif account_number == current_user.account_number: # Internal GlobalPay account
        return jsonify({"success": True, "account_name": current_user.username})
    else:
        return jsonify({"success": False, "message": "Account not found or invalid."}), 404

if __name__ == '__main__':
    app.run(debug=True)
