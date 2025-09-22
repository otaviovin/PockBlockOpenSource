# ========================
# Imports and Dependencies
# ========================

# ==== Flask Framework ====
# Provides tools for building web applications and handling HTTP requests/responses
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort

# ==== Stellar SDK ====
# Tools to interact with the Stellar blockchain (key generation, transaction creation, asset handling, etc.)
from stellar_sdk import Keypair, Asset, TransactionBuilder, Server, Network
from stellar_sdk.exceptions import Ed25519SecretSeedInvalidError, NotFoundError
from stellar_sdk.server import Server  # Redundant but sometimes used for explicitness

# ==== Custom Local Modules ====
# Custom application modules to handle different wallet and blockchain operations
from create_account import CreateAccount
from account_data import AccountData
from generate_account import GenerateAccount
from transaction import Transaction
from receive import Receive
from buy import Buy
from withdraw import Withdraw

# ==== Standard Library ====
# Built-in Python libraries for encoding, randomness, file handling, environment variables, etc.
import csv           # For reading/writing CSV files
import base64        # For base64 encoding/decoding
import binascii      # For binary/ASCII conversions (e.g., hex operations)
import requests      # For making HTTP requests (e.g., APIs)
import random        # For generating random values
import os            # For environment variables and file path handling
import secrets       # For generating cryptographically secure tokens
import json          # For parsing and stringifying JSON data
import datetime      # For working with date and time
from datetime import timedelta  # For calculating expiration or timeout durations

# ==== Environment Variables ====
# To load configuration and secrets from a .env file
from dotenv import load_dotenv

# ==== MongoDB ====
# MongoDB client for accessing the database
from pymongo import MongoClient

# ==== Stripe ====
# Payment processing service integration (for handling card payments)
import stripe

# ==== Fernet ====
# 
from cryptography.fernet import Fernet

# Provides accurate decimal arithmetic, particularly important in financial applications
# - ROUND_DOWN ensures values are truncated, not rounded up
from decimal import Decimal, ROUND_DOWN

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Generate a random secret key for Flask sessions.
# It is recommended that, in production, this key is fixed and securely stored (e.g., environment variable).
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# Define the session expiration time (optional but recommended).
app.permanent_session_lifetime = timedelta(hours=1)

# Security configurations for session cookies.
app.config.update(
    # SESSION_COOKIE_SECURE=True,      # (Production) Cookies are only sent over HTTPS.
    SESSION_COOKIE_SECURE=False,     # (Development) Cookies are only sent over HTTPS.
    SESSION_COOKIE_SAMESITE='Lax',   # Provides basic CSRF protection. Use 'None' if cross-domain.
    SESSION_COOKIE_HTTPONLY=True     # Prevents access via JavaScript (protects against XSS).
)

# Connecting to MongoDB using the URI defined in environment variables
MONGODB_URI = os.getenv("MONGODB_URI")
if not MONGODB_URI:
    raise ValueError("Error: MONGODB_URI is not defined in the .env file")

# Load the encryption key from environment variables
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

# Initializing the MongoDB client using the MongoDB URI with TLS encryption enabled
client = MongoClient(MONGODB_URI, tls=True, tlsAllowInvalidCertificates=True)
data_db = client["datapocketblock"]
data_collection = data_db["userdata"]
ticket_collection = data_db["tickets"]
wallet_data_collection = data_db["wallet_data"]

fernet = Fernet(ENCRYPTION_KEY.encode())

GLOBAL_NETWORK = os.getenv("GLOBAL_NETWORK", "mainnet")
HORIZON_URL = os.getenv("SERVER_URL")  # Server URL

# ====================================
# Secure Session Enforcement
# ====================================

# === Stripe API Keys ===
# Accessing the Stripe public and secret keys from environment variables
stripe_pub_key = os.getenv('STRIPE_PUB_KEY')
stripe_sec_key = os.getenv('STRIPE_SEC_KEY')
stripe.api_key = stripe_sec_key

# ===============================
# Verifying security configuration for the user
# ===============================
# This block ensures that all incoming requests comply with session security standards.
# It is useful to protect against session hijacking, fixation, and unauthorized access.
# Note: These checks should be enforced before handling any user-sensitive routes
# to ensure the session is tied to a consistent client fingerprint (User-Agent + IP).

@app.before_request
def secure_session():
    """
    Enforces session security before processing each request.

    Responsibilities:
    - Mark the session as permanent so it respects the lifetime defined in `PERMANENT_SESSION_LIFETIME`.
    - Generate a secure session ID when the user logs in, if not already set.
    - Validate that the request comes from the same User-Agent and IP address as initially recorded.

    If any validation fails, the session is cleared and access is denied with HTTP 403 Forbidden.

    Note:
    - Be cautious with IP address validation when using proxies or load balancers.
    - HTTPS redirection should be handled at the reverse proxy (e.g., Nginx) if possible.
    """
    session.permanent = True  # Ensures the session respects the defined expiration
    
    if session.get('logged_in'):
        # Generate a secure session ID if not present
        if not session.get('id'):
            session['id'] = os.urandom(16).hex()

        # Validate User-Agent consistency
        user_agent = request.headers.get('User-Agent')
        if not session.get('user_agent'):
            session['user_agent'] = user_agent
        elif session['user_agent'] != user_agent:
            session.clear()
            abort(403)  # Forbidden: session may have been hijacked

        # Validate IP address consistency
        ip = request.remote_addr
        if not session.get('ip'):
            session['ip'] = ip
        elif session['ip'] != ip:
            session.clear()
            abort(403)  # Forbidden: session may have been hijacked

def load_word_list(file_path):
    word_list = []
    try:
        with open(file_path, mode='r', newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)  # Reads the CSV as a dictionary

            for row in reader:
                word_list.append({"letter": row['letter'], "word": row['word']})

            if not word_list:
                raise ValueError("No word_list found in the file.")
            
    except FileNotFoundError:
        raise ValueError(f"The file {file_path} was not found.")
    
    except Exception as e:
        raise ValueError(f"An error occurred while reading the file: {str(e)}")
    
    return word_list

def hex_to_passphrase(hexadecimal):
    """
    Convert a hexadecimal string into a passphrase based on a word list.

    This function takes a hexadecimal string, converts it to binary, splits it 
    into 8-bit blocks, and maps each block to a corresponding word from a CSV 
    word list. The resulting passphrase is a space-separated string of words.

    Args:
        hexadecimal (str): The hexadecimal string to be converted.

    Returns:
        str: The generated passphrase.

    Raises:
        ValueError: If a binary block does not match any word in the word list.
    """

    binary_str = bin(int(hexadecimal, 16))[2:].zfill(len(hexadecimal) * 4)  # Convert the hexadecimal string to binary # Ensures all bits are considered
    byte_blocks = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]  # Split the binary string into 8-bit blocks
    word_list = load_word_list('words_phrase.csv')  # Load the word list from the CSV file
    words = [] # Store the words corresponding to each binary block

    for block in byte_blocks:
        match = next((item['word'] for item in word_list if item['bin'] == block), None)

        if match:
            words.append(match)

        else:
            raise ValueError(f"No matching word found for binary block: {block}")

    return " ".join(words)

def save_wallet_to_db(keypair, seed, seed_phrase, hexadecimal, password=None):
    if wallet_data_collection.find_one({'keypair': keypair}) or wallet_data_collection.find_one({'seed': fernet.encrypt(seed.encode()).decode()}):
        return

    encrypted_data = {
        'keypair': keypair,
        'seed': fernet.encrypt(seed.encode()).decode(),
        'seed_phrase': fernet.encrypt(seed_phrase.encode()).decode(),
        'hexadecimal': fernet.encrypt(hexadecimal.encode()).decode(),
        'password': fernet.encrypt(password.encode()).decode() if password else None
    }

    wallet_data_collection.insert_one(encrypted_data)

def get_accounts_from_db():
    accounts = []
    for doc in wallet_data_collection.find():
        try:
            accounts.append({
                'keypair': doc['keypair'],
                'seed': fernet.decrypt(doc['seed'].encode()).decode(),
                'seed_phrase': fernet.decrypt(doc['seed_phrase'].encode()).decode(),
                'hexadecimal': fernet.decrypt(doc['hexadecimal'].encode()).decode(),
                'password': fernet.decrypt(doc['password'].encode()).decode() if doc.get('password') else None
            })

        except Exception as e:
            print(f"Failed to decrypt document: {e}")

    return accounts

def get_balance():
    keypair = session.get('keypair')
    session['network'] = GLOBAL_NETWORK
    server_url = os.getenv("SERVER_URL") # Server url
    asset_issuer_usdt = os.getenv("USDC_ADDRESS") # Issuer USDC
    asset_issuer_eurc = os.getenv("EURC_ADDRESS") # Issuer EURC
    asset_issuer_brl = os.getenv("BRLC_ADDRESS") # Issuer BRLC
    server = Server(server_url)

    try:
        account = server.accounts().account_id(keypair).call()
        balances = account['balances']

        xlm_balance = "0"
        usdc_balance = "0"
        eurc_balance = "0"
        brlc_balance = "0"
        
        for balance in balances:

            # XLM Balance (native)
            if balance['asset_type'] == 'native':
                xlm_balance = balance['balance']

            # USDC Balance (asset de código USDC)
            elif balance['asset_code'] == 'USDC' or balance['asset_issuer'] == asset_issuer_usdt:
                usdc_balance = balance['balance']

            # EURC Balance (asset de código EURC)
            elif balance['asset_code'] == 'EURC' or balance['asset_issuer'] == asset_issuer_eurc:
                eurc_balance = balance['balance']

            # BRLC Balance (asset de código BRLC)
            elif balance['asset_code'] == 'BRLC' or balance['asset_issuer'] == asset_issuer_brl:
                brlc_balance = balance['balance']

        def safe_float(value):
            try:
                return f"{float(value):.2f}"
            
            except ValueError:
                return "er" 

        xlm_balance = safe_float(xlm_balance)
        usdc_balance = safe_float(usdc_balance)
        eurc_balance = safe_float(eurc_balance)
        brlc_balance = safe_float(brlc_balance)  

        return xlm_balance, usdc_balance, eurc_balance, brlc_balance
                
    except NotFoundError:
        return "er", "er", "er", "er"
    
    except Exception as e:
        print(f"Error: {str(e)}")
        return "er", "er", "er", "er"
    
def get_keypair_and_seed(session, accounts):
    keypair = session.get('keypair')
    seed = session.get('seed')

    if keypair:
        for account in accounts:
            if account['keypair'] == keypair:
                seed = account['seed']
                break

    return keypair, seed

def handle_login(seed_phrase):
    """
    Handles user login using a seed phrase, Stellar secret key, or a password. This function checks 
    if the input matches an existing account in the database or attempts to create a new session from 
    the provided credentials. If the credentials are valid, user session data is set accordingly.

    The function supports the following types of input for authentication:
    - Exact match with a seed phrase, secret key, or password in the database.
    - A 56-character Stellar secret key, which is then converted into a passphrase and associated data.
    - A mnemonic-style passphrase, which is converted back to a Stellar secret key.

    Args:
        seed_phrase (str): A user-provided credential, which can be a seed phrase, 
            a Stellar secret key (56 characters), or a known password.

    Returns:
        bool: True if login was successful, either by finding the account or generating new credentials;
              False otherwise.
    """
    session.clear()
    session.permanent = True
    accounts = get_accounts_from_db()
    account_found = None

    # Check if the seed_phrase matches any saved account
    for account in accounts:
        if account['seed_phrase'] == seed_phrase or account['seed'] == seed_phrase or account['password'] == seed_phrase:
            account_found = account
            break

    if account_found:
        # If account exists, update session with its data
        session.update({
            'logged_in': True,
            'keypair': account_found['keypair'],
            'seed': account_found['seed'],
            'seed_phrase': account_found['seed_phrase'],
            'hexadecimal': account_found['hexadecimal'],
            'password': account_found['password']
        })

        return True
    
    else:
        try:
            session['seed_phrase'] = seed_phrase

            if len(seed_phrase) == 56:
                # Handle Stellar secret key input
                secret_key = seed_phrase
                secret_key_div2 = [seed_phrase[i:i+2] for i in range(0, len(seed_phrase), 2)]
                passphrase_words = []
                word_list = load_word_list('words_phrase.csv')

                # Convert secret key into a passphrase using the word list
                for pair in secret_key_div2:
                    match = next((item['word'] for item in word_list if item['letter'] == pair), None)
                    if match:
                        passphrase_words.append(match)

                    else:
                        session['seed_phrase'] = seed_phrase
                        passphrase_words = seed_phrase.split()

                passphrase = ' '.join(passphrase_words)
                keypair = Keypair.from_secret(secret_key)
                public_key = keypair.public_key
                horizon_url_accounts = f"https://horizon.stellar.org/accounts/{public_key}"
                response = requests.get(horizon_url_accounts)

                if response.status_code == 200:
                    print(f"Account {public_key} exists on the Stellar network.")

                else:
                    print(f"Account {public_key} does not exist on the Stellar network.")

                # Convert secret key to hexadecimal
                secret_key_bytes = base64.b32decode(secret_key, casefold=True)
                hexadecimal = binascii.hexlify(secret_key_bytes).decode()
                password = ''.join([str(random.randint(0, 9)) for _ in range(5)])

                # Store credentials in the session and database
                session.update({
                    'logged_in': True,
                    'keypair': public_key,
                    'seed': secret_key,
                    'seed_phrase': seed_phrase,
                    'hexadecimal': hexadecimal,
                    'password': password
                })

                save_wallet_to_db(public_key, secret_key, passphrase, hexadecimal, password)

            else:
                # Handle mnemonic passphrase input
                passphrase = seed_phrase
                words = passphrase.split()
                letters = []

                for word in words:
                    match = next((item['letter'] for item in word_list if item['word'] == word), None)
                    if match:
                        letters.append(match)

                    else:
                        raise ValueError(f"Word not found in word_list: {word}")

                secret_key = ''.join(letters)
                keypair = Keypair.from_secret(secret_key)
                public_key = keypair.public_key
                horizon_url = f"https://horizon.stellar.org/accounts/{public_key}"
                response = requests.get(horizon_url)

                if response.status_code == 200:
                    print(f"Account {public_key} exists on the Stellar network.")

                else:
                    print(f"Account {public_key} does not exist on the Stellar network.")

                secret_key_bytes = base64.b32decode(secret_key, casefold=True)
                hexadecimal = binascii.hexlify(secret_key_bytes).decode()
                password = ''.join([str(random.randint(0, 9)) for _ in range(5)])

                session['logged_in'] = True
                session['keypair'] = public_key
                session['seed'] = secret_key
                session['seed_phrase'] = passphrase
                session['hexadecimal'] = hexadecimal
                session['password'] = password

                save_wallet_to_db(public_key, secret_key, passphrase, hexadecimal, password)

            return True

        except Exception as e:
            return False

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        seed_phrase = request.form.get('passphrase')

        if seed_phrase:

            if handle_login(seed_phrase):
                return redirect(url_for('main'))
            
            else:
                return render_template('login.html', error='Incorrect passphrase or secret key. Please try again.')

        else:
            return render_template('login.html', error='Please enter a password or passphrase or secret key.')

    return render_template('login.html')

@app.route('/app', methods=['GET', 'POST'])
def login_app():
    if request.method == 'POST':
        seed_phrase = request.form.get('passphrase')

        if seed_phrase:
            if handle_login(seed_phrase):
                return redirect(url_for('main_app'))
            
            else:
                return render_template('login_app.html', error='Incorrect passphrase or secret key. Please try again.')

        else:
            return render_template('login_app.html', error='Please enter a password or passphrase or secret key.')

    return render_template('login_app.html')

def handle_main(is_app=False):
    """
    Function ...
    """
    if not session.get('logged_in'):
        return redirect(url_for('login_app' if is_app else 'login'))
    ########## Common Session Data ##########
    session['network'] = GLOBAL_NETWORK
    network = session['network']
    xlm_balance, usdc_balance, eurc_balance, brl_balance = get_balance()
    keypair = session.get('keypair')
    seed = session.get('seed')
    #########################################
    accounts = get_accounts_from_db()
    selected_keypair = request.args.get('selected_keypair') or request.form.get('selected_keypair')

    if selected_keypair:
        session['keypair'] = selected_keypair
        
        for account in accounts:

            if account['keypair'] == selected_keypair:
                session['seed'] = account['seed']
                session['seed_phrase'] = account['seed_phrase']
                session['hexadecimal'] = account['hexadecimal']
                session['password'] = account.get('password', '') 
                break

    if keypair:
        for account in accounts:
            if account['keypair'] == keypair:
                keypair = account['keypair']
                seed = account['seed']
                break

    xlm_balance, usdc_balance, eurc_balance, brl_balance = get_balance()

    return render_template('main_app.html' if is_app else 'main.html', keypair=keypair, seed=seed, accounts=accounts, 
        network=network, xlm_balance=xlm_balance, usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance
        )

@app.route('/main', methods=['GET', 'POST'])
def main():
    return handle_main(is_app=False)

@app.route('/main_app', methods=['GET', 'POST'])
def main_app():
    return handle_main(is_app=True)

def handle_create_account(is_app=False):
    """
    Function ...
    """
    if not session.get('logged_in'):
        return redirect(url_for('login_app' if is_app else 'login'))
    ########## Common Session Data ##########
    session['network'] = GLOBAL_NETWORK
    network = session['network']
    xlm_balance, usdc_balance, eurc_balance, brl_balance = get_balance()
    keypair = session.get('keypair')
    seed = session.get('seed')
    #########################################

    if request.method == 'POST':
        password = request.form['password']
        asset_code = request.form['asset_code']
        amount = request.form['amount']
        base_fee = 100
        account = CreateAccount(amount, base_fee, seed, network, password, asset_code)
        message = account.execute()

        return render_template('create_account_app.html' if is_app else 'create_account.html', message=message, keypair=keypair, 
            seed=seed, network=network, xlm_balance=xlm_balance, usdc_balance=usdc_balance, 
            eurc_balance=eurc_balance, brl_balance=brl_balance
            )

    return render_template('create_account_app.html' if is_app else 'create_account.html', keypair=keypair, seed=seed, network=network, 
        xlm_balance=xlm_balance, usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance
        )

@app.route('/createaccount', methods=["GET", "POST"])
def create_account():
    return handle_create_account(is_app=False)

@app.route('/createaccount_app', methods=["GET", "POST"])
def create_account_app():
    return handle_create_account(is_app=True)

def handle_account_data(is_app=False):
    """
    Function ...
    """
    if not session.get('logged_in'):
        return redirect(url_for('login_app' if is_app else 'login'))
    ########## Common Session Data ##########
    session['network'] = GLOBAL_NETWORK
    network = session['network']
    xlm_balance, usdc_balance, eurc_balance, brl_balance = get_balance()
    keypair = session.get('keypair')
    seed = session.get('seed')
    #########################################
    transaction_list = []
    balance_list = []
    trustlines = {"USDC": False, "EURC": False, "BRLC": False}

    if request.method == 'POST':
        address = keypair

        if address and network:
            account_data_instance = AccountData(account=address, network=network)
            message = account_data_instance.execute()
            transaction_list = account_data_instance.transaction_list
            balance_list = account_data_instance.balance_list
            trustlines = account_data_instance.trustlines

        else:
            message = (f"<br>Address or network not provided.<br>")

        return render_template('account_data_app.html' if is_app else 'account_data.html', message=message, keypair=keypair, 
            seed=seed, network=network, xlm_balance=xlm_balance, usdc_balance=usdc_balance, eurc_balance=eurc_balance, 
            brl_balance=brl_balance, transaction_list=transaction_list, balance_list=balance_list, trustlines=trustlines
            )

    return render_template(
        'account_data_app.html' if is_app else 'account_data.html', keypair=keypair, seed=seed, network=network, 
        xlm_balance=xlm_balance, usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance, 
        transaction_list=transaction_list, balance_list=balance_list, trustlines=trustlines
        )

@app.route('/account_data', methods=['GET', 'POST'])
def account_data():
    return handle_account_data(is_app=False)

@app.route('/account_data_app', methods=['GET', 'POST'])
def account_data_app():
    return handle_account_data(is_app=True)

def handle_forget_all(is_app=False):
    """
    Deletes all wallet data from the MongoDB collection and redirects to a confirmation page.

    Parameters:
        is_app (bool): If True, redirects to the mobile app confirmation page.
                       If False, redirects to the web confirmation page.

    Returns:
        Response: A Flask redirect response to the appropriate confirmation page.
    """

    wallet_data_collection.delete_many({})

    return redirect(url_for('forget_all_app.html' if is_app else 'forget_all.html'))

@app.route('/forget_all', methods=['POST'])
def forget_all():
    return handle_forget_all(is_app=False)

@app.route('/forget_all_app', methods=['POST'])
def forget_all_app():
    return handle_forget_all(is_app=True)

@app.route('/logout', methods=['POST'])
def logout():

    session.clear()
    return redirect(url_for('login'))

@app.route('/logout_app', methods=['POST'])
def logout_app():

    session.clear()
    return redirect(url_for('login_app'))

def handle_save_network(is_app=False):
    """
    Function ...
    """
    network = GLOBAL_NETWORK
    session['network'] = network

    return redirect(url_for('main_app' if is_app else 'main'))

@app.route('/save_network', methods=['POST'])
def save_network():
    return handle_save_network(is_app=False)

@app.route('/save_network_app', methods=['POST'])
def save_network_app():
    return handle_save_network(is_app=True)

def handle_generate_account(is_app=False):
    """
    Function ...
    """
    if request.method == 'POST':
        password = request.json.get('password')
        public_key = session.get('public_key')
        secret_key = session.get('secret_key')
        passphrase = session.get('passphrase')
        keys_match = session.get('keys_match')
        generate_account_instance = GenerateAccount(public_key=public_key, secret_key=secret_key, passphrase=passphrase, keys_match=keys_match)
        response = generate_account_instance.execute()

        if isinstance(response, str):
            return response
        
        return render_template('login_app.html' if is_app else 'login.html')

    return render_template('login_app.html' if is_app else 'login.html')

@app.route('/generate_account', methods=['POST'])
def generate_account():
    return handle_generate_account(is_app=False)

@app.route('/generate_account_app', methods=['POST'])
def generate_account_app():
    return handle_generate_account(is_app=True)

def handle_select_account(is_app=False):
    """
    Function ...
    """
    selected_keypair = request.form.get('selected_keypair')
    accounts = get_accounts_from_db()

    for account in accounts:

        if account['keypair'] == selected_keypair:
            session['keypair'] = account['keypair']
            session['seed'] = account['seed']
            session['seed_phrase'] = account['seed_phrase']
            session['hexadecimal'] = account['hexadecimal']
            session['password'] = account.get('password', '') 
            break

    return redirect(url_for('main_app.html' if is_app else 'main.html'))

@app.route('/select_account', methods=['POST'])
def select_account():
    return handle_select_account(is_app=False)

@app.route('/select_account_app', methods=['POST'])
def select_account_app():
    return handle_select_account(is_app=True)

def handle_forget_account(is_app=False):
    """
    Remove the selected Stellar account from the MongoDB database and session.
    """
    selected_keypair = request.form.get('selected_keypair')

    if not selected_keypair:
        return "No account selected", 400

    # Remove from MongoDB
    result_forget_Account = wallet_data_collection.delete_one({'keypair': selected_keypair})

    if session.get('keypair') == selected_keypair:
        session.clear()

    if result_forget_Account.deleted_count == 0:
        return "Account not found in database.", 404

    return redirect(url_for('main_app' if is_app else 'main'))

@app.route('/forget_account', methods=['POST'])
def forget_account():
    return handle_forget_account(is_app=False)

@app.route('/forget_account_app', methods=['POST'])
def forget_account_app():
    return handle_forget_account(is_app=True)

def handle_buy(is_app=False):
    """
    Function ...
    """
    if not session.get('logged_in'):
        return redirect(url_for('login_app' if is_app else 'login'))
    ########## Common Session Data ##########
    session['network'] = GLOBAL_NETWORK
    network = session['network']
    xlm_balance, usdc_balance, eurc_balance, brl_balance = get_balance()
    keypair = session.get('keypair')
    seed = session.get('seed')
    #########################################

    accounts = get_accounts_from_db()
    qr_code_base64 = None
    message = None
    responsecopyandpaste = None

    if request.method == 'GET':
        message = request.args.get("message")
        return render_template(
            'buy_app.html' if is_app else 'buy.html', message=message, network=network, keypair=keypair, seed=seed, xlm_balance=xlm_balance, 
            usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance, qr_code_base64=qr_code_base64, 
            responsecopyandpaste=responsecopyandpaste
            )
    
    if request.method == 'POST':
        buy_asset_code = request.form['buy_asset_code']
        buy_amount = request.form['buy_amount']
        address = keypair
        buy_name = request.form.get('buy_name', None)
        buy_idnumber = request.form.get('buy_idnumber', None)
        buy_type = request.form.get('buy_type', None)
        card_name = request.form.get('card_name', None)
        buy_email = request.form.get('buy_email', None)
        buy_country = request.form.get('country', None)
        description_buy = request.form.get('description_buy_idnumber', None)

        try:  
            if buy_type == "pix":
                try:
                    buy_instance = Buy(
                        network=network, keypair=keypair, seed=seed, 
                        buy_asset_code=buy_asset_code, buy_amount=buy_amount, 
                        address=address, accounts=accounts, xlm_balance=xlm_balance, 
                        usdc_balance=usdc_balance, eurc_balance=eurc_balance, 
                        brl_balance=brl_balance
                    )

                    qr_code_base64, message, responsecopyandpaste = buy_instance.generate_pix_code(
                        buy_name=buy_name, buy_idnumber=buy_idnumber, buy_type=buy_type, description_buy=description_buy
                    )
                
                except Exception as e:
                    message = (f"<br>Error creating PIX charge: {str(e)}<br>")

                    return render_template(
                    'buy_app.html' if is_app else 'buy.html', message=message, network=network, keypair=keypair, seed=seed, 
                    buy_asset_code=buy_asset_code, buy_amount=buy_amount, address=address, accounts=accounts, xlm_balance=xlm_balance, 
                    usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance, qr_code_base64=qr_code_base64, 
                    responsecopyandpaste=responsecopyandpaste
                    )

            elif buy_type == "credit_card":
                try:
                    buy_instance = Buy(
                        network=network, keypair=keypair, seed=seed, 
                        buy_asset_code=buy_asset_code, buy_amount=buy_amount, 
                        address=address, accounts=accounts, xlm_balance=xlm_balance, 
                        usdc_balance=usdc_balance, eurc_balance=eurc_balance, 
                        brl_balance=brl_balance
                    )
                            
                    message = buy_instance.generate_stripe_charge(
                        buy_name=buy_name, buy_idnumber=buy_idnumber, buy_type=buy_type, card_name=card_name, buy_email=buy_email, buy_country=buy_country, description_buy=description_buy
                    )

                except Exception as e:
                    message = (f"<br>Error creating Credit Card charge: {str(e)}<br>")

                    return render_template(
                    'buy_app.html' if is_app else 'buy.html', message=message, network=network, keypair=keypair, seed=seed, 
                    buy_asset_code=buy_asset_code, buy_amount=buy_amount, address=address, accounts=accounts, xlm_balance=xlm_balance, 
                    usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance, qr_code_base64=qr_code_base64, 
                    responsecopyandpaste=responsecopyandpaste
                    )

        except Exception as e:
            message = (f"<br>Error.<br>")
        
            return render_template(
                    'buy_app.html' if is_app else 'buy.html', message=message, network=network, keypair=keypair, seed=seed, 
                    buy_asset_code=buy_asset_code, buy_amount=buy_amount, address=address, accounts=accounts, xlm_balance=xlm_balance, 
                    usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance, qr_code_base64=qr_code_base64, 
                    responsecopyandpaste=responsecopyandpaste
                    )

    return render_template(
        'buy_app.html' if is_app else 'buy.html', message=message, network=network, keypair=keypair, seed=seed, xlm_balance=xlm_balance, 
        usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance, qr_code_base64=qr_code_base64, 
        responsecopyandpaste=responsecopyandpaste
        )

@app.route('/buy', methods=['GET', 'POST'])
def buy():
    return handle_buy(is_app=False)

@app.route('/buy_app', methods=['GET', 'POST'])
def buy_app():
    return handle_buy(is_app=True)

def handle_transaction(is_app=False):
    """
    Function ...
    """
    if not session.get('logged_in'):
        return redirect(url_for('login_app' if is_app else 'login'))
    ########## Common Session Data ##########
    session['network'] = GLOBAL_NETWORK
    network = session['network']
    xlm_balance, usdc_balance, eurc_balance, brl_balance = get_balance()
    keypair = session.get('keypair')
    seed = session.get('seed')
    #########################################
    asset_code = request.args.get('asset_code', '')
    destination_account = request.args.get('destination_account', '')
    amount_sell = request.args.get('amount_sell', '')

    if request.method == 'POST':
        seed = session.get('seed')
        keypair = session.get('keypair')
        asset_code = request.form['asset_code']
        sender_asset_code = request.form['sender_asset_code']
        destination_account = request.form['destination_account']
        amount_sell = request.form['amount_sell']

        if network:
            transaction_instance = Transaction(network=network, keypair=keypair, seed=seed, asset_code=asset_code, sender_asset_code=sender_asset_code, destination_account=destination_account, amount_sell=amount_sell)
            message = transaction_instance.execute()

        else:
            message = (f"<br>Address or network not provided.<br>")

        return render_template(
            'transaction_app.html' if is_app else 'transaction.html', message=message, network=network, keypair=keypair, seed=seed, 
            asset_code=asset_code, sender_asset_code=sender_asset_code, destination_account=destination_account, 
            amount_sell=amount_sell, xlm_balance=xlm_balance, usdc_balance=usdc_balance, 
            eurc_balance=eurc_balance, brl_balance=brl_balance
            )
    
    return render_template(
        'transaction_app.html' if is_app else 'transaction.html', keypair=keypair, seed=seed, network=network, xlm_balance=xlm_balance, usdc_balance=usdc_balance, 
        eurc_balance=eurc_balance, brl_balance=brl_balance, asset_code=request.args.get('asset_code', ''), 
        destination_account=request.args.get('destination_account', ''), amount_sell=request.args.get('amount_sell', '')
        )

@app.route('/transaction', methods=['GET', 'POST'], strict_slashes=False)
def transaction():
    return handle_transaction(is_app=False)

@app.route('/transaction_app', methods=['GET', 'POST'], strict_slashes=False)
def transaction_app():
    return handle_transaction(is_app=True)

def handle_update_taxes_transaction(is_app=False):
    """
    Handle the calculation of transaction fees for a given asset and amount.
    This function retrieves the fee settings from MongoDB, calculates both
    percentage-based and fixed fees, and returns the final amount after fees.

    Parameters:
    - is_app (bool): If True, the request is coming from the mobile app version.
    
    Returns:
    - JSON response containing the calculated fees and final amount,
      or an error message if something goes wrong.
    """
    if not session.get('logged_in'):
        return redirect(url_for('login_app' if is_app else 'login'))
    ########## Common Session Data ##########
    session['network'] = GLOBAL_NETWORK
    network = session['network']
    xlm_balance, usdc_balance, eurc_balance, brl_balance = get_balance()
    keypair = session.get('keypair')
    seed = session.get('seed')
    #########################################

    try:
        # Parse JSON data sent in the request
        data = request.json
        amount = Decimal(data.get("amount", "0"))
        asset_code = data.get("sender_asset_code")
        receiver_asset_code = data.get("receiver_asset_code")

        # ======= Retrieve fee settings directly from MongoDB =======
        data_db_withdraw = client["withdrawpocketblock"]
        settings_collection = data_db_withdraw["settings_value_fiat"]

        # Select the fee settings based on the asset code
        if asset_code == "USDC" and receiver_asset_code == "USDC":
            settings_usd = settings_collection.find_one({"withdraw_type": "USD"})
            perc_fee = Decimal(settings_usd["fee"])
            usd_value_sender = Decimal(settings_usd["value"])
            usd_value_receiver = Decimal(settings_usd["value"])

        elif asset_code == "EURC" and receiver_asset_code == "EURC":
            settings_eur = settings_collection.find_one({"withdraw_type": "EUR"})
            perc_fee = Decimal(settings_eur["fee"])
            eur_value_sender = Decimal(settings_eur["value"])
            eur_value_receiver = Decimal(settings_eur["value"])

        else:
            # If the asset is not supported, return a JSON error response
            return jsonify({"success": False, "error": "Asset não suportado"}), 400
        # ===========================================================

        # Calculate the fees
        fee_percent_amount = (amount * perc_fee) # Fee based on percentage
        final_amount = amount + fee_percent_amount # Amount remaining after deducting total fee

        # Return a JSON response with all fee details and final amount
        return jsonify({
            "success": True,
            "asset": asset_code,
            "amount": str(amount),
            "fee_percent": str(perc_fee),
            "amount_fee": str(fee_percent_amount),
            "final_amount": str(final_amount)
        })

    except Exception as e:
        # Catch any unexpected errors and return a JSON error response
        return jsonify({"success": False, "error": f"Erro interno: {e}"}), 500  

@app.route('/update-taxes-transaction', methods=['GET', 'POST'], strict_slashes=False)
def update_taxes_transactiontransaction():
    return handle_update_taxes_transaction(is_app=False)

@app.route('/update-taxes-transaction_app', methods=['GET', 'POST'], strict_slashes=False)
def update_taxes_transactiontransaction_app():
    return handle_update_taxes_transaction(is_app=True)

def handle_withdraw(is_app=False):
    """
    Function ...
    """
    if not session.get('logged_in'):
        return redirect(url_for('login_app' if is_app else 'login'))
    ########## Common Session Data ##########
    session['network'] = GLOBAL_NETWORK
    network = session['network']
    xlm_balance, usdc_balance, eurc_balance, brl_balance = get_balance()
    keypair = session.get('keypair')
    seed = session.get('seed')
    #########################################

    if request.method == 'POST':
        seed = session.get('seed')
        keypair = session.get('keypair')
        withdraw_asset_code = request.form.get('withdraw_asset_code', None)
        withdraw_amount = request.form.get('withdraw_amount', None)
        withdraw_name = request.form.get('withdraw_name', None)
        withdraw_idnumber = request.form.get('withdraw_idnumber', None)
        description_withdraw = request.form.get('description_withdraw', None)
        withdraw_type = request.form.get('withdraw_type', None)
        withdraw_bank = request.form.get('withdraw_bank', None)
        withdraw_bank_ag = request.form.get('withdraw_bank_ag', None)
        withdraw_bank_cc = request.form.get('withdraw_bank_cc', None)
        withdraw_country = request.form.get('country', None)
        withdraw_pix = request.form.get('withdraw_pix', None)

        if not keypair or not withdraw_asset_code or not withdraw_amount or not withdraw_name or not withdraw_idnumber or not withdraw_type or not withdraw_country:

            if is_app:
                return render_template('withdraw_app.html', message="Erro: Todos os campos obrigatórios precisam ser preenchidos.")

            return render_template('withdraw.html', message="Erro: Todos os campos obrigatórios precisam ser preenchidos.")

        withdraw_instance = Withdraw(
            network=network,
            keypair=keypair,
            seed=seed,
            withdraw_asset_code=withdraw_asset_code,
            withdraw_amount=withdraw_amount,
            withdraw_fiat=withdraw_asset_code
        )

        message = withdraw_instance.withdraw_transaction(
            withdraw_amount=withdraw_amount,
            withdraw_name=withdraw_name,
            withdraw_asset=withdraw_asset_code,
            withdraw_idnumber=withdraw_idnumber,
            description_withdraw=description_withdraw,
            withdraw_type=withdraw_type,
            withdraw_bank=withdraw_bank,
            withdraw_bank_ag=withdraw_bank_ag,
            withdraw_bank_cc=withdraw_bank_cc,
            withdraw_country=withdraw_country,
            withdraw_pix=withdraw_pix,
            withdraw_fiat=withdraw_asset_code
        )

        return render_template(
            'withdraw_app.html' if is_app else 'withdraw.html', keypair=keypair, seed=seed, message=message, xlm_balance=xlm_balance, 
            usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance
            )

    return render_template('withdraw_app.html' if is_app else 'withdraw.html', keypair=keypair, seed=seed, xlm_balance=xlm_balance, 
        usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance
        )

@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    return handle_withdraw(is_app=False)

@app.route('/withdraw_app', methods=['GET', 'POST'])
def withdraw_app():
    return handle_withdraw(is_app=True)

def handle_receive(is_app=False):
    """
    Function ...
    """
    if not session.get('logged_in'):
        return redirect(url_for('login_app' if is_app else 'login'))
    ########## Common Session Data ##########
    session['network'] = GLOBAL_NETWORK
    network = session['network']
    xlm_balance, usdc_balance, eurc_balance, brl_balance = get_balance()
    keypair = session.get('keypair')
    seed = session.get('seed')
    #########################################
    qr_code_base64 = None
    message = None
    qr_data = None

    if request.method == 'POST':

        seed = session.get('seed')
        keypair = session.get('keypair')

        if not seed or not keypair:
            return redirect(url_for('login_app' if is_app else 'login'))

        asset_code = request.form['receive_asset_code']
        amount_receive = request.form['amount_receive']
        text_memo = None

        if not asset_code or not amount_receive:

            message = (f"<br>The asset code or the amount to be received was not provided.<br>")
            
            return render_template(
                'receive_app.html' if is_app else 'receive.html', message=message, keypair=keypair, seed=seed, network=network, 
                xlm_balance=xlm_balance, usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance, 
                qr_code_base64=qr_code_base64, qr_data=qr_data
                )

        receiver = Receive(network, keypair, seed, text_memo, amount_receive, asset_code)
        qr_code_base64, message, qr_data = receiver.execute()

    return render_template('receive_app.html' if is_app else 'receive.html', message=message, keypair=keypair, seed=seed, 
        network=network, xlm_balance=xlm_balance, usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance, 
        qr_code_base64=qr_code_base64, qr_data=qr_data
        )

@app.route('/receive', methods=['GET', 'POST'], strict_slashes=False)
def receive():
    return handle_receive(is_app=False)

@app.route('/receive_app', methods=['GET', 'POST'], strict_slashes=False)
def receive_app():
    return handle_receive(is_app=True)

def handle_settings(is_app=False):
    """
    Function ...
    """
    if not session.get('logged_in'):
        return redirect(url_for('login_app' if is_app else 'login'))
    ########## Common Session Data ##########
    session['network'] = GLOBAL_NETWORK
    network = session['network']
    xlm_balance, usdc_balance, eurc_balance, brl_balance = get_balance()
    keypair = session.get('keypair')
    seed = session.get('seed')
    #########################################
    message = None
    existing_user = data_collection.find_one({"keypair": keypair})

    if existing_user:
        settings = {
            "name": existing_user.get("name", ""),
            "email": existing_user.get("email", ""),
            "idnumber": existing_user.get("idnumber", ""),
            "phone_number": existing_user.get("phone_number", ""),
            "resaddress": existing_user.get("resaddress", ""),
            "country": existing_user.get("country", ""),
        }

    else:
        settings = {}

    if request.method == 'POST':
        name = request.form.get('name_settings')
        idnumber = request.form.get('idnumber_settings')
        email = request.form.get('email_settings')
        phone_number = request.form.get('phone_settings')
        resaddress = request.form.get('address_settings')
        country = request.form.get('country_settings')

        try:

            if keypair and name and idnumber and email and phone_number and resaddress and country:

                existing_user = data_collection.find_one({"keypair": keypair})

                if existing_user:

                    user_data = {
                        "keypair": keypair,
                        "name": name,
                        "idnumber": idnumber,
                        "email": email,
                        "phone_number": phone_number,
                        "resaddress": resaddress,
                        "country": country,
                        "user": "activated",
                        "settings_datetime": datetime.datetime.utcnow()
                    }

                    data_collection.update_one({"keypair": keypair}, {"$set": user_data})

                    message = (f"<br>Data saved successfuly.<br>")

                else:
                    source_secret = os.getenv("MAINNET_FUNDER_SECRET")
                    source_keypair = Keypair.from_secret(source_secret)
                    source_public = source_keypair.public_key
                    horizon_url = HORIZON_URL
                    # network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE
                    network_passphrase = Network.PUBLIC_NETWORK_PASSPHRASE
                    server = Server(horizon_url=horizon_url)
                    source_account = server.load_account(account_id=source_public)
                    source_account_clean = source_account.split("#")[0].strip()

                    # Make a transaction of 2.5 XLM to activate the account
                    transaction = (
                        TransactionBuilder(
                            source_account=source_account_clean,
                            network_passphrase=network_passphrase,
                            base_fee=100
                        )
                        .add_text_memo("Activating account!")
                        .append_payment_op(
                            destination=keypair,
                            amount="2.5",
                            asset=Asset.native()
                        )
                        .set_timeout(30)
                        .build()
                    )

                    transaction.sign(source_keypair)
                    response = server.submit_transaction(transaction)

                    # Verifica se a transação foi bem-sucedida antes de salvar no MongoDB
                    if response and response.get("successful", False):
                        user_data = {
                            "keypair": keypair,
                            "name": name,
                            "idnumber": idnumber,
                            "email": email,
                            "phone_number": phone_number,
                            "resaddress": resaddress,
                            "country": country,
                            "user": "activated",
                            "settings_datetime": datetime.datetime.utcnow()
                        }

                        data_collection.insert_one(user_data)

                        message = (f"Data saved successfuly.<br>Account activated.<br>")

                    else:

                        user_data = {
                            "keypair": keypair,
                            "name": name,
                            "idnumber": idnumber,
                            "email": email,
                            "phone_number": phone_number,
                            "resaddress": resaddress,
                            "country": country,
                            "user": "desactivated",
                            "settings_datetime": datetime.datetime.utcnow()
                        }

                        data_collection.insert_one(user_data)

                        message = (f"Data saved successfuly, but account is not acctivated yet!<br>")  
            
            else:
                message = (f"Please fill in all fields before saving.<br>" )

            return render_template('settings_app.html' if is_app else 'settings.html', message=message, keypair=keypair, seed=seed, network=network, 
                    xlm_balance=xlm_balance, usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance, 
                    settings=user_data
                    )
        
        except Exception as e:
            message = (f"Error during transaction. Check your transaction parameters.<br>")
            
            return render_template('settings_app.html' if is_app else 'settings.html', message=message, keypair=keypair, seed=seed, network=network, 
                xlm_balance=xlm_balance, usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance, 
                settings=settings
                )
    
    return render_template('settings_app.html' if is_app else 'settings.html', message=message, keypair=keypair, seed=seed, network=network, 
        xlm_balance=xlm_balance, usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance, 
        settings=settings
        )

# Rota web
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    return handle_settings(is_app=False)

# Rota app
@app.route('/settings_app', methods=['GET', 'POST'])
def settings_app():
    return handle_settings(is_app=True)

@app.route('/home', methods=['GET', 'POST'])
def home():
    return render_template('home.html') 

@app.route('/home_app', methods=['GET', 'POST'])
def home_app():
    return render_template('home_app.html')

@app.route('/create_trustline', methods=['POST'])
def create_trustline():
    try:
        secret_key = session.get('seed') # Retrieve the user's Stellar secret key from the session
        if not secret_key:
            return jsonify({'success': False, 'message': 'Secret key error.'}), 400
        
        data = request.json # Get the asset data sent in the JSON body of the request
        asset_code  = data.get('asset')
        if not asset_code:
            return jsonify({'success': False, 'message': 'Asset code error.'}), 400

        if secret_key and asset_code: # Determine the correct issuer address based on asset type
            if asset_code == 'USDC':
                asset_issuer = os.getenv("USDC_ADDRESS")
            elif asset_code == 'EURC':
                asset_issuer = os.getenv("EURC_ADDRESS")
            else:
                return jsonify({'success': False, 'message': 'Invalid asset code.'}), 400

            if not asset_issuer.startswith("G") or len(asset_issuer) != 56: # Validate the issuer public key format
                return jsonify({'success': False, 'message': 'Invalid issuer public key.'}), 400

            try:
                # Load the user's keypair and public key
                keypair = Keypair.from_secret(secret_key)
                public_key = keypair.public_key
                server = Server(horizon_url=HORIZON_URL)
                network_passphrase = Network.PUBLIC_NETWORK_PASSPHRASE # network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE
                account = server.accounts().account_id(public_key).call() # Load the user's account to get current balances
                balances = account.get('balances', [])
                existing_trustlines = sum(1 for b in balances if b['asset_type'] != 'native') # Count how many trustlines already exist (non-native assets)
                native_balance = 0 # Get the native XLM balance
                
                for b in balances:
                    if b['asset_type'] == 'native':
                        native_balance = float(b['balance'])
                        break

                # Calculate minimum balance required for the new trustline
                base_reserve = 0.5  # Each trustline requires 0.5 XLM
                num_entries = existing_trustlines + 1  # Adding 1 for the new trustline
                min_balance_required = 1 + (num_entries * base_reserve)  # 1 XLM base + 0.5 XLM per entry

                # Check if the account has enough XLM to support the new trustline
                if native_balance < min_balance_required:
                    print(f"Insufficient balance to create trustline. Minimum required: {min_balance_required:.2f} XLM, current: {native_balance:.2f} XLM.")
                    return jsonify({
                        'success': False,
                        'message': f'Insufficient balance to create trustline.'
                    }), 400 # Minimum required: {min_balance_required:.2f} XLM, current: {native_balance:.2f} XLM.

                # Build the transaction to create the trustline
                source_account = server.load_account(public_key)
                asset_obj = Asset(code=asset_code, issuer=asset_issuer)
                
                transaction = (
                    TransactionBuilder(
                        source_account=source_account,
                        network_passphrase=network_passphrase,
                        base_fee=100
                    )
                    .append_change_trust_op(asset=asset_obj)
                    .set_timeout(30)
                    .build()
                )

                # Sign and submit the transaction
                transaction.sign(keypair)
                response = server.submit_transaction(transaction)
                return jsonify({'success': True, 'message': 'Trustline created'}), 200

            # Handle specific error if the secret key is invalid
            except Ed25519SecretSeedInvalidError:
                message = ("<br>Invalid secret key.<br>")
                return message
            
            # Handle any unexpected error
            except Exception as e:
                return f"<br>Unexpected error: {str(e)}<br>"

    except Exception as e:
        if hasattr(e, 'extras'):
            print(json.dumps(e.extras, indent=2))
            return jsonify({'success': False, 'message': 'Erro Horizon', 'details': e.extras}), 500
        
        return jsonify({'success': False, 'message': str(e)}), 500

def handle_help(is_app=False):
    """
    Function ...
    """
    if not session.get('logged_in', False):
        return redirect(url_for('login_app' if is_app else 'login'))
    ########## Common Session Data ##########
    session['network'] = GLOBAL_NETWORK
    network = session['network']
    xlm_balance, usdc_balance, eurc_balance, brl_balance = get_balance()
    keypair = session.get('keypair')
    seed = session.get('seed')
    #########################################

    if request.method == 'POST':
        name = request.form.get('name_help')
        email = request.form.get('email_help')
        phone_number = request.form.get('phone_help')
        type = request.form.get('type_help')
        description = request.form.get('description_help')

        if not seed or not keypair:
            # Se não encontrar seed ou keypair na sessão, redireciona para a página de login
            return redirect(url_for('login' if not is_app else 'login_app', keypair=keypair, seed=seed, network=network))
        
        try:
            existing_user = data_collection.find_one({"keypair": keypair})

            if existing_user:

                ticket_data = {
                    "keypair": keypair,
                    "name": name,
                    "email": email,
                    "phone_number": phone_number,
                    "type": type,
                    "description": description,
                    "help_datetime": datetime.datetime.utcnow()
                }

                ticket_collection.insert_one(ticket_data)

                message = (
                f"<br>Ticket registred.<br>"
                f"<br><button id='closeNotificationBtn' onclick='closeNotification()'><i class='fas fa-times'></i> Fechar</button>"
                )

            else:
                message = (
                f"<br>No account found.<br>"
                f"<br><button id='closeNotificationBtn' onclick='closeNotification()'><i class='fas fa-times'></i> Fechar</button>"
                )

        except Exception as e:
            message = (
                f"<br>Error during open ticket.<br>"
                f"<br><button id='closeNotificationBtn' onclick='closeNotification()'><i class='fas fa-times'></i> Fechar</button>"
                )
            
        return render_template('help_app.html' if is_app else 'help.html', message=message, keypair=keypair, seed=seed, network=network)

    return render_template('help_app.html' if is_app else 'help.html', 
        keypair=keypair, seed=seed, network=network, xlm_balance=xlm_balance, 
        usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance
        )

@app.route('/help', methods=['GET', 'POST'])
def help():
    return handle_help(is_app=False)

@app.route('/help_app', methods=['GET', 'POST'])
def help_app():
    return handle_help(is_app=True)

def handle_support(is_app=False):
    """
    Function ...
    """
    if not session.get('logged_in', False):
        return redirect(url_for('login_app' if is_app else 'login'))
    ########## Common Session Data ##########
    session['network'] = GLOBAL_NETWORK
    network = session['network']
    xlm_balance, usdc_balance, eurc_balance, brl_balance = get_balance()
    keypair = session.get('keypair')
    seed = session.get('seed')
    #########################################

    if request.method == 'POST':

        if not seed or not keypair:
            return redirect(url_for('login' if not is_app else 'login_app', 
                                    keypair=keypair, seed=seed, network=network))

    return render_template('support_app.html' if is_app else 'support.html', 
                           keypair=keypair, seed=seed, network=network)

# Rota web
@app.route('/support', methods=['GET', 'POST'])
def support():
    return handle_support(is_app=False)

# Rota app
@app.route('/support_app', methods=['GET', 'POST'])
def support_app():
    return handle_support(is_app=True)

def handle_faq(is_app=False):
    """
    Function ...
    """
    if not session.get('logged_in', False):
        return redirect(url_for('login_app' if is_app else 'login'))
    ########## Common Session Data ##########
    session['network'] = GLOBAL_NETWORK
    network = session['network']
    xlm_balance, usdc_balance, eurc_balance, brl_balance = get_balance()
    keypair = session.get('keypair')
    seed = session.get('seed')
    #########################################

    if request.method == 'POST':

        if not seed or not keypair:
            return redirect(url_for('login' if not is_app else 'login_app', keypair=keypair, seed=seed, network=network))

    return render_template('faq_app.html' if is_app else 'faq.html', keypair=keypair, seed=seed, network=network)

# Rota web
@app.route('/faq', methods=['GET', 'POST'])
def faq():
    return handle_faq(is_app=False)

# Rota app
@app.route('/faq_app', methods=['GET', 'POST'])
def faq_app():
    return handle_faq(is_app=True)

@app.route('/get_stripe_public_key')
def get_stripe_public_key():
    """
    Return the Stripe public key used for client-side Stripe.js initialization.

    Returns:
        Response: JSON object with the Stripe publishable key.

        Example:
            {
                "stripe_public_key": "pk_test_XXXXXXXXXXXXXXXXXXXX"
            }

    Notes:
        - The public key is read from the environment variable STRIPE_PUB_KEY.
        - This route is typically used by the frontend to configure Stripe.
    """
    return jsonify({'stripe_public_key': os.getenv('STRIPE_PUB_KEY')})

@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    if request.method == "GET":
        return jsonify({"status": "OK"}), 200
    
    try:
        data = request.json

        if not data:
            return jsonify({"error": "Invalid request"}), 400  

        return jsonify({"status": "OK"}), 200

    except Exception as e:
        return jsonify({"error": "Internal error"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)