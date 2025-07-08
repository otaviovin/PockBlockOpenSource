from flask import Flask, render_template, request, redirect, url_for, session, jsonify 
from stellar_sdk import Keypair, Asset, TransactionBuilder, Server, Keypair, Network
from stellar_sdk.exceptions import Ed25519SecretSeedInvalidError, NotFoundError
from stellar_sdk.server import Server
from create_account import CreateAccount
from account_data import AccountData
from generate_account import GenerateAccount
from transaction import Transaction
from receive import Receive
from buy import Buy
from withdraw import Withdraw
import csv
import base64
import binascii
import requests
import random
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from datetime import timedelta
import datetime
import secrets
import json

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

# Initializing the MongoDB client using the MongoDB URI with TLS encryption enabled
client = MongoClient(MONGODB_URI, tls=True, tlsAllowInvalidCertificates=True)
data_db = client["datapocketblock"]
data_collection = data_db["userdata"]
ticket_collection = data_db["tickets"]

# Actual paths to the CSV files
WALLET_DATA_FILE_PATH = "./wallet_data.csv"

# Creates the uploads folder if it does not exist
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load environment variables from .env file
load_dotenv()

GLOBAL_NETWORK = os.getenv("GLOBAL_NETWORK", "mainnet")
HORIZON_URL = os.getenv("SERVER_URL")  # Server URL

@app.before_request
def secure_session():
    """Ensures the session is secure and correctly renewed."""
    session.permanent = True  # Ensures the session respects the defined expiration
    if session.get('logged_in') and not session.get('id'):
        session['id'] = os.urandom(16).hex()  # Generates a new session ID

def load_word_list(file_path):
    word_list = []
    try:
        with open(file_path, mode='r', newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)  # Reads the CSV as a dictionary

            for row in reader:
                print(f"Row read from file: {row}")  # Adding print to see content
                word_list.append({"letter": row['letter'], "word": row['word']})
                print(word_list)

            if not word_list:
                raise ValueError("No word_list found in the file.")
            
    except FileNotFoundError:
        raise ValueError(f"The file {file_path} was not found.")
    
    except Exception as e:
        raise ValueError(f"An error occurred while reading the file: {str(e)}")
    
    return word_list

def hex_to_passphrase(hexadecimal):
    # Converte o hexadecimal para binário
    binary_str = bin(int(hexadecimal, 16))[2:].zfill(len(hexadecimal) * 4)  # Garante que todos os bits sejam considerados
    byte_blocks = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)] # Divide o binário em blocos de 8 bits
    word_list = load_word_list('words_phrase.csv') # Carrega a word_list do arquivo CSV
    words = [] # Encontra as palavras correspondentes aos blocos binários

    for block in byte_blocks:
        match = next((item['word'] for item in word_list if item['bin'] == block), None)

        if match:
            words.append(match)

        else:
            raise ValueError(f"No matching word found for binary block: {block}")

    return " ".join(words)

def save_to_csv(keypair, seed, seed_phrase, hexadecimal, password=None):
    file_path = 'wallet_data.csv'
    # Ler o conteúdo atual do arquivo CSV
    rows = []

    try:
        with open(file_path, mode='r', newline='') as file:
            reader = csv.reader(file)
            rows = list(reader)

    except FileNotFoundError:
        rows = []

    # Verificar se a seed ou keypair já existem no arquivo
    for row in rows:
        if keypair in row or seed in row:
            print("Seed or Keypair already exists in the CSV file.")
            return  # Não adiciona nada se a seed ou keypair já estiver presente

    # Se não existir, adicionar a nova linha com a senha
    with open(file_path, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([keypair, seed, seed_phrase, hexadecimal, password])
        print("New record added to CSV file.")

def get_accounts_from_csv():
    accounts = []
    file_path = 'wallet_data.csv'

    try:
        with open(file_path, mode='r', newline='') as file:
            reader = csv.reader(file)

            for row in reader:

                if len(row) >= 5:  # Certificar-se de que todas as colunas estão presentes
                    accounts.append({
                        'keypair': row[0],
                        'seed': row[1],
                        'seed_phrase': row[2],
                        'hexadecimal': row[3],
                        'password': row[4]  # Adiciona a senha ao dicionário
                    })

                elif len(row) == 4:  # Caso a senha não esteja presente (linhas antigas)
                    accounts.append({
                        'keypair': row[0],
                        'seed': row[1],
                        'seed_phrase': row[2],
                        'hexadecimal': row[3],
                        'password': None
                    })

    except FileNotFoundError:
        print("CSV file not found.")

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

        # Variáveis para armazenar os saldos
        xlm_balance = "0"
        usdc_balance = "0"
        eurc_balance = "0"
        brlc_balance = "0"
        
        for balance in balances:

            # Saldo XLM (nativo)
            if balance['asset_type'] == 'native':
                xlm_balance = balance['balance']

            # Saldo USDC (asset de código USDC)
            elif balance['asset_code'] == 'USDC' or balance['asset_issuer'] == asset_issuer_usdt:
                usdc_balance = balance['balance']

            # Saldo EURC (asset de código EURC)
            elif balance['asset_code'] == 'EURC' or balance['asset_issuer'] == asset_issuer_eurc:
                eurc_balance = balance['balance']

            # Saldo BRLC (asset de código BRLC)
            elif balance['asset_code'] == 'BRLC' or balance['asset_issuer'] == asset_issuer_brl:
                brlc_balance = balance['balance']

        # Função para tratar a conversão de valores para float e lidar com erros
        def safe_float(value):
            try:
                return f"{float(value):.2f}"
            
            except ValueError:
                return "er"  # Retorna "er" em caso de erro

        # Conversão dos saldos para float, com tratamento de erros
        xlm_balance = safe_float(xlm_balance)
        usdc_balance = safe_float(usdc_balance)
        eurc_balance = safe_float(eurc_balance)
        brlc_balance = safe_float(brlc_balance)  

        return xlm_balance, usdc_balance, eurc_balance, brlc_balance
                
    except NotFoundError:
        # return "er", "er", "er", "er"
        return "er", "er", "er", "er"
    
    except Exception as e:
        print(f"Error: {str(e)}")
        return "er", "er", "er", "er"
    
def get_keypair_and_seed(session, accounts):
    keypair = session.get('keypair')
    seed = session.get('seed')

    # Atualiza keypair e seed se necessário
    if keypair:
        for account in accounts:
            if account['keypair'] == keypair:
                seed = account['seed']
                break

    return keypair, seed

def handle_login(seed_phrase):
    session.clear()
    session.permanent = True
    accounts = get_accounts_from_csv()
    account_found = None

    # Verificar se o seed_phrase corresponde a algum registro de conta
    for account in accounts:

        if account['seed_phrase'] == seed_phrase or account['seed'] == seed_phrase or account['password'] == seed_phrase:
            account_found = account
            break

    # 🔹 Se a conta já existe, apenas preenche a sessão e retorna True
    if account_found:
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
                secret_key = seed_phrase
                secret_key_div2 = [seed_phrase[i:i+2] for i in range(0, len(seed_phrase), 2)]
                passphrase_words = []
                word_list = load_word_list('words_phrase.csv')

                for pair in secret_key_div2:
                    match = next((item['word'] for item in word_list if item['letter'] == pair), None)

                    if match:
                        passphrase_words.append(match)

                    else:
                        print(f"Par de letras não encontrado na word_list: {pair}")
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

                secret_key_bytes = base64.b32decode(secret_key, casefold=True)
                hexadecimal = binascii.hexlify(secret_key_bytes).decode()
                password = ''.join([str(random.randint(0, 9)) for _ in range(5)])

                session.update({
                    'logged_in': True,
                    'keypair': public_key,
                    'seed': secret_key,
                    'seed_phrase': seed_phrase,
                    'hexadecimal': hexadecimal,
                    'password': password
                })

                save_to_csv(public_key, secret_key, passphrase, hexadecimal, password)

            else:
                # Caso seja uma passphrase
                passphrase = seed_phrase
                words = passphrase.split()
                letters = []

                for word in words:
                    match = next((item['letter'] for item in word_list if item['word'] == word), None)

                    if match:
                        letters.append(match)

                    else:
                        raise ValueError(f"Palavra não encontrada na word_list: {word}")

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

                save_to_csv(public_key, secret_key, passphrase, hexadecimal, password)

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
    if not session.get('logged_in'):
        return redirect(url_for('login_app' if is_app else 'login'))

    ########## Common Session Data ##########
    session['network'] = GLOBAL_NETWORK
    network = session['network']
    xlm_balance, usdc_balance, eurc_balance, brl_balance = get_balance()
    keypair = session.get('keypair')
    seed = session.get('seed')
    #########################################
    accounts = get_accounts_from_csv()
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
            message = (
                f"<br>"
                f"Address or network not provided.<br>"
                f"<br>"
            )

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

    csv_file_path = 'wallet_data.csv'
    open(csv_file_path, 'w').close()
    session.clear()

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
    network = GLOBAL_NETWORK
    session['network'] = network

    return redirect(url_for('main_app.html' if is_app else 'main.html'))

@app.route('/save_network', methods=['POST'])
def save_network():
    return handle_save_network(is_app=False)

@app.route('/save_network_app', methods=['POST'])
def save_network_app():
    return handle_save_network(is_app=True)

def handle_generate_account(is_app=False):
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
    selected_keypair = request.form.get('selected_keypair')
    accounts = get_accounts_from_csv()

    for account in accounts:

        if account['keypair'] == selected_keypair:
            session['keypair'] = account['keypair']
            session['seed'] = account['seed']
            session['seed_phrase'] = account['seed_phrase']
            session['hexadecimal'] = account['hexadecimal']
            session['password'] = account.get('password', '')  # Adiciona a senha à sessão, se necessário
            break

    return redirect(url_for('main_app.html' if is_app else 'main.html'))

@app.route('/select_account', methods=['POST'])
def select_account():
    return handle_select_account(is_app=False)

@app.route('/select_account_app', methods=['POST'])
def select_account_app():
    return handle_select_account(is_app=True)

def handle_forget_account(is_app=False):
    selected_keypair = request.form.get('selected_keypair')

    if not selected_keypair:
        return "No account selected", 400

    updated_accounts = []
    file_path = 'wallet_data.csv'

    with open(file_path, mode='r', newline='') as file:
        reader = csv.reader(file)
        for row in reader:

            if row[0] != selected_keypair:
                updated_accounts.append(row)

    with open(file_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(updated_accounts)

    if session.get('keypair') == selected_keypair:
        session.clear()

    return redirect(url_for('main_app.html' if is_app else 'main.html'))

@app.route('/forget_account', methods=['POST'])
def forget_account():
    return handle_forget_account(is_app=False)

@app.route('/forget_account_app', methods=['POST'])
def forget_account_app():
    return handle_forget_account(is_app=True)

def handle_buy(is_app=False):
    if not session.get('logged_in'):
        return redirect(url_for('login_app' if is_app else 'login'))

    ########## Common Session Data ##########
    session['network'] = GLOBAL_NETWORK
    network = session['network']
    xlm_balance, usdc_balance, eurc_balance, brl_balance = get_balance()
    keypair = session.get('keypair')
    seed = session.get('seed')
    #########################################
    accounts = get_accounts_from_csv() 
    qr_code_base64 = None
    message = None
    responsecopyandpaste = None
    
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
        description_buy = request.form.get('description_buy', None)
        print(f"buy type: {buy_type}")

        buy_instance = Buy(
            network=network, keypair=keypair, seed=seed, 
            buy_asset_code=buy_asset_code, buy_amount=buy_amount, 
            address=address, accounts=accounts, xlm_balance=xlm_balance, 
            usdc_balance=usdc_balance, eurc_balance=eurc_balance, 
            brl_balance=brl_balance
        )

        if buy_type == "PIX":
            qr_code_base64, message, responsecopyandpaste = buy_instance.generate_pix_code(
                buy_name=buy_name, buy_idnumber=buy_idnumber, buy_type=buy_type, description_buy=description_buy
            )

        elif buy_type == "CreditCard":
            message = buy_instance.generate_stripe_charge(
                buy_name=buy_name, buy_idnumber=buy_idnumber, buy_type=buy_type, card_name=card_name, buy_email=buy_email, buy_country=buy_country, description_buy=description_buy
            )

        if not buy_amount and not message:
            message = (
                f"<br>"
                f"Error generating payment URL.<br>"
                f"<br>"
            )

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
            message = (
                f"<br>"
                f"Address or network not provided.<br>"
                f"<br>"
            )

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

@app.route('/transaction', methods=['GET', 'POST'])
def transaction():
    return handle_transaction(is_app=False)

@app.route('/transaction_app', methods=['GET', 'POST'])
def transaction_app():
    return handle_transaction(is_app=True)

def handle_withdraw(is_app=False):
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
    Função principal para processar o recebimento de ativos.
    :param is_app: Booleano que indica se é um aplicativo ou versão web.
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
            # Garantindo que os dados sejam fornecidos
            message = (
                f"<br>"
                f" The asset code or the amount to be received was not provided.<br>"
                f"<br>"
            )
            
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

@app.route('/receive', methods=['GET', 'POST'])
def receive():
    return handle_receive(is_app=False)

@app.route('/receive_app', methods=['GET', 'POST'])
def receive_app():
    return handle_receive(is_app=True)

def handle_settings(is_app=False):
    """
    Função principal para processar as configurações do usuário.
    :param is_app: Booleano que indica se é um aplicativo ou versão web.
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
            "phone_number": existing_user.get("phone_number", ""),
            "resaddress": existing_user.get("resaddress", ""),
        }

    else:
        settings = {}

    if request.method == 'POST':
        name = request.form.get('name_settings')
        idnumber = request.form.get('idnumber_settings')
        email = request.form.get('email_settings')
        phone_number = request.form.get('phone_settings')
        resaddress = request.form.get('address_settings')

        try:

            if keypair and name and idnumber and email and phone_number and resaddress:

                existing_user = data_collection.find_one({"keypair": keypair})

                if existing_user:

                    user_data = {
                        "keypair": keypair,
                        "name": name,
                        "idnumber": idnumber,
                        "email": email,
                        "phone_number": phone_number,
                        "resaddress": resaddress,
                        "user": "activated",
                        "settings_datetime": datetime.datetime.utcnow()
                    }

                    data_collection.update_one({"keypair": keypair}, {"$set": user_data})

                    message = (
                        f"Data saved successfuly.<br>"
                        f"<button id='closeNotificationBtn' onclick='closeNotification()'><i class='fas fa-times'></i> Fechar</button>"
                        )

                else:
                    source_secret = os.getenv("MAINNET_FUNDER_SECRET")
                    source_keypair = Keypair.from_secret(source_secret)
                    source_public = source_keypair.public_key
                    horizon_url = HORIZON_URL
                    # network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE
                    network_passphrase = Network.PUBLIC_NETWORK_PASSPHRASE
                    server = Server(horizon_url=horizon_url)
                    source_account = server.load_account(account_id=source_public)

                    print(source_secret)
                    print(source_keypair)
                    print(source_public)
                    print(source_account)

                    # Make a transaction of 2.5 XLM toi activate the account
                    transaction = (
                        TransactionBuilder(
                            source_account=source_account,
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
                    print(response)

                    # Verifica se a transação foi bem-sucedida antes de salvar no MongoDB
                    if response and response.get("successful", False):
                        user_data = {
                            "keypair": keypair,
                            "name": name,
                            "idnumber": idnumber,
                            "email": email,
                            "phone_number": phone_number,
                            "resaddress": resaddress,
                            "user": "activated",
                            "settings_datetime": datetime.datetime.utcnow()
                        }

                        data_collection.insert_one(user_data)

                        message = (
                            f"Data saved successfuly.<br>"
                            f"account activated.<br>"
                            f"<button id='closeNotificationBtn' onclick='closeNotification()'><i class='fas fa-times'></i> Fechar</button>"
                            )

                    else:

                        user_data = {
                            "keypair": keypair,
                            "name": name,
                            "idnumber": idnumber,
                            "email": email,
                            "phone_number": phone_number,
                            "resaddress": resaddress,
                            "user": "desactivated",
                            "settings_datetime": datetime.datetime.utcnow()
                        }

                        data_collection.insert_one(user_data)

                        message = (
                            f"Data saved successfuly, but account is not acctivated yet!<br>"
                            f"<button id='closeNotificationBtn' onclick='closeNotification()'><i class='fas fa-times'></i> Fechar</button>"
                            )  
            
            else:
                print("Please fill in all fields before saving.")
                message = (
                    f"Please fill in all fields before saving.<br>"
                    f"<button id='closeNotificationBtn' onclick='closeNotification()'><i class='fas fa-times'></i> Fechar</button>"
                )

            return render_template('settings_app.html' if is_app else 'settings.html', message=message, keypair=keypair, seed=seed, network=network, 
                    xlm_balance=xlm_balance, usdc_balance=usdc_balance, eurc_balance=eurc_balance, brl_balance=brl_balance, 
                    settings=user_data
                    )
        
        except Exception as e:
            print("Error during transaction - check your transaction parameters: ", e)
            message = (
                f"Error during transaction - check your transaction parameters.<br>"
                f"<button id='closeNotificationBtn' onclick='closeNotification()'><i class='fas fa-times'></i> Fechar</button>"
                )
            
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
        seed = session.get('seed')
        keypair = session.get('keypair')
        session['network'] = GLOBAL_NETWORK
        network = session['network']
        data = request.json
        asset = data.get('asset')

        secret_key = session.get('seed')
        if not secret_key:
            print(f"Chave secreta não encontrada na sessão")
            raise ValueError("A chave secreta não foi fornecida.")
            # return jsonify({'success': False, 'message': 'Chave secreta não encontrada na sessão'}), 400

        if asset == 'USDC':
            asset_issuer = os.getenv("USDC_ADDRESS")
        elif asset == 'EURC':
            asset_issuer = os.getenv("EURC_ADDRESS")
        else:
            message = (
                    f"<br>"
                    f" Sender asset invalid.<br>"
                    f"<br>"
                )
            return message       

        try:
            keypair = Keypair.from_secret(secret_key)

        except Ed25519SecretSeedInvalidError:
            raise ValueError("A chave secreta fornecida é inválida.")

        keypair = Keypair.from_secret(secret_key)
        public_key = keypair.public_key
        horizon_url = HORIZON_URL
        # network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE
        network_passphrase = Network.PUBLIC_NETWORK_PASSPHRASE
        server = Server(horizon_url=horizon_url)
        source_account = server.load_account(public_key)
        asset = Asset(asset, asset_issuer)

        transaction = (
            TransactionBuilder(
                source_account=source_account,
                network_passphrase=network_passphrase,
                base_fee=100
            )
            .append_change_trust_op(asset=asset)
            .set_timeout(30)
            .build()
        )

        transaction.sign(keypair)

        response = server.submit_transaction(transaction)
        return jsonify({'success': True, 'message': 'Trustline created'}), 200

    except Exception as e:
        if hasattr(e, 'extras'):
            print(f"Erro Horizon")
            print(json.dumps(e.extras, indent=2))
            return jsonify({'success': False, 'message': 'Erro Horizon', 'details': e.extras}), 500
        
        print(f"Error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

def handle_help(is_app=False):
    """
    Função principal para processar a página de ajuda.
    :param is_app: Booleano que indica se é um aplicativo ou versão web.
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

                print("Ticket registred.")
                message = (
                f"<br>"
                f"Ticket registred.<br>"
                f"<br>"
                f"<button id='closeNotificationBtn' onclick='closeNotification()'><i class='fas fa-times'></i> Fechar</button>"
                )

            else:
                print("No account found.")
                message = (
                f"<br>"
                f"No account found.<br>"
                f"<br>"
                f"<button id='closeNotificationBtn' onclick='closeNotification()'><i class='fas fa-times'></i> Fechar</button>"
                )

        except Exception as e:
            print("Error during open ticket.", e)
            message = (
                f"<br>"
                f"Error during open ticket.<br>"
                f"<br>"
                f"<button id='closeNotificationBtn' onclick='closeNotification()'><i class='fas fa-times'></i> Fechar</button>"
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
    Função principal para processar a página de suporte.
    :param is_app: Booleano que indica se é um aplicativo ou versão web.
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
    Função principal para processar a página de faq.
    :param is_app: Booleano que indica se é um aplicativo ou versão web.
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
    return jsonify({'stripe_public_key': os.getenv('STRIPE_PUB_KEY')})

@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    if request.method == "GET":
        return jsonify({"status": "OK"}), 200
    
    try:
        data = request.json

        if not data:
            print("Requisição inválida: corpo vazio.")
            return jsonify({"error": "Requisição inválida"}), 400  

        print(f"Dados recebidos no webhook: {data}")
        return jsonify({"status": "OK"}), 200

    except Exception as e:
        print(f"[WEBHOOK]|[ERROR] - Erro no webhook: {str(e)}")
        return jsonify({"error": "Erro interno"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)