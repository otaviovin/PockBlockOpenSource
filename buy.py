import os
import random
import string
import base64
import qrcode
import datetime
from io import BytesIO
from dotenv import load_dotenv
from efipay import EfiPay
from pymongo import MongoClient
from decimal import Decimal, ROUND_DOWN
import requests
import json
import stripe
from flask import request

# Load environment variables from .env file
load_dotenv()

GLOBAL_NETWORK = os.getenv("GLOBAL_NETWORK", "mainnet")
HORIZON_URL = os.getenv("SERVER_URL") # Server url
PIX_KEY = os.getenv("PIX_KEY")

# Access Stripe variables
stripe_pub_key = os.getenv('STRIPE_PUB_KEY')
stripe_sec_key = os.getenv('STRIPE_SEC_KEY')

# Configuração do Stripe com a chave secreta
stripe.api_key = stripe_sec_key

# Configuração do MongoDB
client = MongoClient(os.getenv("MONGODB_URI"))
db_buy = client["buypocketblock"]
buys_collection = db_buy["buys"]
settings_collection = db_buy["settings_value_fiat"]
data_db_buy = client["datapocketblock"]
data_collection = data_db_buy["userdata"]

class Buy:
    """
    A class to handle the buying of assets using Stellar blockchain transactions.

    Attributes:
        network (str): The network to use for the transaction ('mainnet' or 'testnet').
        keypair (Keypair): The keypair for the Stellar account.
        seed (str): The seed phrase for the Stellar account.
        buy_asset_code (str): The asset code to buy ('XLM', 'USDC', 'EURC', 'BRLC').
        buy_amount (float): The amount of the asset to buy.
        address (str): The wallet address to send the bought asset.
        accounts (list): A list of account data from the CSV file.
    """

    BASE_URL_GERENCIANET = os.getenv("BASE_URL_GERENCIANET")
    # BASE_URL_GERENCIANET = "https://api.gerencianet.com.br"

    def __init__(self, network, keypair, seed, buy_asset_code, buy_amount, address, accounts, xlm_balance, usdc_balance, eurc_balance, brl_balance):
        """
        Initializes a new instance of the Buy class.

        Args:
            network (str): The network to use ('mainnet' or 'testnet').
            keypair (Keypair): The keypair for the Stellar account.
            seed (str): The seed phrase for the Stellar account.
            buy_asset_code (str): The asset code to buy ('XLM', 'USDC', 'EURC', 'BRLC').
            buy_amount (float): The amount of the asset to buy.
            address (str): The wallet address to send the bought asset.
            accounts (list): A list of account data from the CSV file.
            xlm_balance (float): The XLM balance of the account.
            usdc_balance (float): The USDC balance of the account.
            eurc_balance (float): The EURC balance of the account.
            brl_balance (float): The BRLC balance of the account.
            self.BASE_URL_EFI ():
            self.API_KEY_EFI ():
        """
        self.network = network
        self.keypair = keypair
        self.seed = seed
        self.buy_asset_code = buy_asset_code
        self.buy_amount = buy_amount
        self.address = address
        self.accounts = accounts
        self.BASE_URL_EFI = os.getenv("BASE_URL_EFI")
        self.API_KEY_EFI = os.getenv("API_KEY_EFI")
 
    def generate_pix_code(self, buy_name, buy_idnumber, description_buy, buy_type):
        """
        Generate a PIX code using the Gerencianet API for payment processing.

        Gera um txid pegando os 10 primeiros caracteres da chave pública
        e completando com caracteres aleatórios até atingir entre 26 e 35 caracteres.

        Args:
            keypair (Keypair): A Keypair do Stellar.
            buy_name (str): Name.
            buy_idnumber (str): ID Number.
            buy_type (str): 
            description_buy (str): Description.

        Returns:
            str: Um txid válido.
        """

        existing_user = data_collection.find_one({"keypair": self.keypair})

        if existing_user:
            min_length = 26
            max_length = 35
            txid_base = self.keypair[:10] # Pegar os 10 primeiros caracteres da chave pública
            total_length = random.randint(min_length, max_length) # Definir tamanho total aleatório dentro do intervalo permitido
            random_chars = ''.join(random.choices(string.ascii_letters + string.digits, k=total_length - len(txid_base))) # Gerar caracteres aleatórios para completar o restante do txid
            self.txid = txid_base + random_chars
            buy_address_account = self.keypair

            credentials = {
                "client_id": os.getenv("CLIENT_ID"),
                "client_secret": os.getenv("CLIENT_SECRET"),
                "sandbox": os.getenv("SANDBOX"), 
                "certificate": os.getenv("CERTIFICATE")
            }

            if not all([credentials["client_id"], credentials["client_secret"], credentials["certificate"]]):
                print(f"Gerencianet credentials were not loaded correctly.")
                message = (
                    f"<br>"
                    "Gerencianet credentials were not loaded correctly.<br><br"
                    f"<br>"
                )
                return "Error", message, "Error"

            try:
                if self.buy_asset_code == "USDC":
                    try:
                        settings = settings_collection.find_one({"buy_type": "USD"})
                        fee_buy = settings["fee"]
                        value_usd = settings["value"]
                        buy_amount = (Decimal(self.buy_amount) + (Decimal(self.buy_amount) * Decimal(fee_buy))) *  Decimal(value_usd)
                        buy_amount_usd = Decimal(self.buy_amount) + (Decimal(self.buy_amount) * Decimal(fee_buy))
                        buy_amount_value = buy_amount.quantize(Decimal("0.01"), rounding=ROUND_DOWN)
                            
                    except (ValueError, TypeError) as e:
                        print(f"Error applying percbuy.")
                        message = (
                            f"<br>"
                            f"Error applying percbuy: {e}.<br><br"
                            f"<br>"
                        )
                        return "Error", message, "Error"
                    
                elif self.buy_asset_code == 'EURC':
                    try:
                        settings = settings_collection.find_one({"buy_type": "EUR"})
                        fee_buy = settings["fee"]
                        value_eur = settings["value"]
                        buy_amount = (Decimal(self.buy_amount) + (Decimal(self.buy_amount) * Decimal(fee_buy))) *  Decimal(value_eur)
                        buy_amount_eur = Decimal(self.buy_amount) + (Decimal(self.buy_amount) * Decimal(fee_buy))
                        buy_amount_value = buy_amount.quantize(Decimal("0.01"), rounding=ROUND_DOWN)
                            
                    except (ValueError, TypeError) as e:
                        print(f"Error applying percbuy.")
                        message = (
                            f"<br>"
                            f"Error applying percbuy: {e}.<br><br"
                            f"<br>"
                        )
                        return "Error", message, "Error"
                else:
                    print(f"Error defining settings.")
                
            except (ValueError, TypeError):
                print(f"The purchase amount is not valid.")
                message = (
                    f"<br>"
                    f"The purchase amount is not valid.<br><br"
                    f"<br>"
                )
                return "Error", message, "Error"

            body_buy_amount = "{:.2f}".format(buy_amount_value)
            pix_key = PIX_KEY

            auth = base64.b64encode(
            (f"{credentials['client_id']}:{credentials['client_secret']}"
            ).encode()).decode()

            url_auth = "https://pix.api.efipay.com.br/oauth/token"

            payload="{\r\n    \"grant_type\": \"client_credentials\"\r\n}"
            headers = {
            'Authorization': f"Basic {auth}",
            'Content-Type': 'application/json'
            }

            response_auth = requests.request("POST",
                                    url_auth,
                                    headers=headers,
                                    data=payload,
                                    cert=credentials['certificate'])

            print(f"response_auth: {response_auth.text}")

            access_token = response_auth.json().get("access_token")
            txid = self.txid
            print(f"txid: {txid}")
            url_pix_create_charge = f"https://pix.api.efipay.com.br/v2/cob/{txid}"

            body = {
                'calendario': {
                    'expiracao': 3600
                },
                'devedor': {
                    'cpf': buy_idnumber,
                    'nome': buy_name
                },
                'valor': {
                    'original': body_buy_amount
                },
                'chave': pix_key,
                'solicitacaoPagador': description_buy
            }

            headers_charge = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }

            try:
                print(f"Trying to create a pix_create_charge")
                response_charge = requests.put(
                    url_pix_create_charge,
                    headers=headers_charge,
                    data=json.dumps(body),
                    cert=credentials['certificate']
                )

                print(f"Resposta da criação da cobrança", response_charge.text)
                response = json.loads(response_charge.text)
                print(response)
                
            except Exception as e:
                print(f"Error in pix_create_charge: {e}")
                print(f"[ERROR] pix_create_charge failed: {type(e).__name__}: {str(e)}")
                message = (
                    f"<br>"
                    f"<br>Error creating PIX charge: {str(e)}<br>"
                    f"<br>"
                ) 
                return "Error", message, "Error"
            
            responseqrcode = response["loc"]["location"]
            responsecopyandpaste = response["pixCopiaECola"]
            # qr_img_pix = qrcode.make(responseqrcode)  # Create the QR code from the data
            qr_img_pix = qrcode.make(responsecopyandpaste, box_size=10, border=1)  # Adjust box_size for larger QR code. Resize the QR code (larger box_size and border)
            qr_img_pix = qr_img_pix.convert("RGB")  # Convert to RGB mode for Pillow compatibility. Ensure the image is compatible with Pillow
            img_byte_arr = BytesIO() # Save the QR code image to memory and prepare for sending
            qr_img_pix.save(img_byte_arr, format='PNG')  # Save as PNG
            img_byte_arr.seek(0)        
            qr_code_base64 = base64.b64encode(img_byte_arr.getvalue()).decode("utf-8") # Encode the image as base64 (if required by the application)

            url_detail = f"https://pix.api.efipay.com.br/v2/cob/{txid}"

            headers_detail = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }

            response_detail_raw = requests.get(url_detail, headers=headers_detail, cert=credentials['certificate'])
            print("Response detail raw:", response_detail_raw.text)

            response_detail = response_detail_raw.json()
            print("Response detail parsed:", response_detail)

            # Verificar se o status é 'ATIVA'
            if response_detail.get("status") == "ATIVA":
                pix_status = response_detail.get("status") # Generate an HTML message with the payment details and the QR code link

                # Salvar transação no MongoDB
                transaction_data = {
                    "txid": self.txid,
                    "buy_address_account": buy_address_account,
                    "buy_name": buy_name,
                    "buy_idnumber": buy_idnumber,
                    "buy_type": buy_type,
                    "buy_email": None,
                    "buy_description": description_buy,
                    "buy_asset_code": self.buy_asset_code,
                    "buy_amount": self.buy_amount,
                    "buy_address": self.address,
                    "pix_status": pix_status,
                    "buy_card_name": None,
                    "credit_card_status": None,
                    "buy_status": "PENDENTE",
                    "buy_transaction_id": None,
                    "transaction_datetime": datetime.datetime.utcnow()
                }

                buys_collection.insert_one(transaction_data)

                message = (
                    f"<br>"
                    f"<strong>QR Code PIX: </strong><br>"
                    f"<strong>Link:</strong> <a href='{responsecopyandpaste}' target='_blank'>{responsecopyandpaste}</a><br>"
                    f"<br>"
                )
                return qr_code_base64, message, responsecopyandpaste
            
            else:
                # Caso o status não seja 'ATIVA', você pode retornar outro código ou tratar o erro
                print(f"Transaction status is not active.")
                message = (
                    f"<br>"
                    f"Transaction status is not active."
                    f"<br>"
                )
                return "Error", message, "Error"
            
        else:
            # Caso o status não seja 'ATIVA', você pode retornar outro código ou tratar o erro
            print(f"Please, activate your account.")
            message = (
                f"<br>"
                f"Please, activate your account.<br>"
                f"You can activate your account filling the settings information<br>"
                f"<br>"
            )
            return "Error", message, "Error"
        
    def generate_stripe_charge(self, buy_name, buy_idnumber, description_buy, buy_type, buy_email, card_name):
        """
        Generate a flow for payment processing.

        Gera um txid pegando os 10 primeiros caracteres da chave pública
        e completando com caracteres aleatórios até atingir entre 26 e 35 caracteres.

        Args:
            keypair (Keypair): A Keypair do Stellar.
            buy_name (str): Name.
            buy_idnumber (str): ID Number.
            buy_type (str): 
            buy_email (str): 
            card_name (str): 
            description_buy (str): Description.

        Returns:
            str: Um txid válido.
        """
        keypair = self.keypair
        print(f"keypair: {keypair}")
        existing_user = data_collection.find_one({"keypair": keypair})

        if existing_user:
            print("User exists in MongoDB")
            min_length = 26
            max_length = 35
            txid_base = self.keypair[:10] # Pegar os 10 primeiros caracteres da chave pública
            total_length = random.randint(min_length, max_length) # Definir tamanho total aleatório dentro do intervalo permitido
            random_chars = ''.join(random.choices(string.ascii_letters + string.digits, k=total_length - len(txid_base))) # Gerar caracteres aleatórios para completar o restante do txid
            self.txid = txid_base + random_chars
            payment_method_id = request.form['payment_method_id']
            buy_address_account = self.keypair
            print(f"payment_method_id: {payment_method_id}")

            if self.buy_asset_code == "USDC":
                try:
                    settings = settings_collection.find_one({"buy_type": "USD"})
                    fee_buy = settings["fee"]
                    buy_amount = (Decimal(self.buy_amount) + (Decimal(self.buy_amount) * Decimal(fee_buy))) * 100
                    buy_amount_value = buy_amount.quantize(Decimal("0.01"), rounding=ROUND_DOWN)
                            
                except (ValueError, TypeError) as e:
                    print(f"Error applying percbuy.")
                    message = (
                        f"<br>"
                        f"Error applying percbuy: {e}.<br><br"
                        f"<br>"
                    )
                    return message
                    
            elif self.buy_asset_code == 'EURC':
                try:
                    settings_eur = settings_collection.find_one({"buy_type": "EUR"})
                    settings_usd = settings_collection.find_one({"buy_type": "USD"})
                    fee_buy = settings_eur["fee"]
                    value_eur = settings_eur["value"]
                    value_usd = settings_usd["value"]
                    buy_amount = ((Decimal(self.buy_amount) + (Decimal(self.buy_amount) * Decimal(fee_buy))) * (Decimal(value_eur) / (Decimal(value_usd)))) * 100
                    buy_amount_value = buy_amount.quantize(Decimal("0.01"), rounding=ROUND_DOWN)
                            
                except (ValueError, TypeError) as e:
                    print(f"Error applying percbuy.")
                    message = (
                        f"<br>"
                        f"Error applying percbuy: {e}.<br><br"
                        f"<br>"
                    )
                    return message
            else:
                print(f"Error defining settings.")

            body_buy_amount = "{:.2f}".format(buy_amount_value)
            txid = self.txid
            amount_in_cents = int(round(buy_amount_value))
            print(f"amount_in_cents: {amount_in_cents}")

            # Criação da cobrança no Stripe
            payment_intent = stripe.PaymentIntent.create(
                amount=amount_in_cents,  # Valor em centavos, ajuste conforme necessário
                currency='usd',
                payment_method=payment_method_id,
                confirm=True, # Confirma o pagamento diretamente
                automatic_payment_methods={
                    'enabled': True,  # Habilita métodos automáticos de pagamento
                    'allow_redirects': 'never'  # Impede redirecionamentos, se necessário
                },
                return_url='https://suaurl.com/return',  # URL de retorno após pagamento
            )

            if payment_intent.status == 'succeeded':
                transaction_id = payment_intent.id
                amount = payment_intent.amount
                currency = payment_intent.currency
                status = payment_intent.status
                payment_date = datetime.datetime.utcnow()

                print(f"transaction_id: {transaction_id}")
                print(f"amount: {amount}")
                print(f"currency: {currency}")
                print(f"status: {status}")
                print(f"payment_date: {payment_date}")

                # Salvar transação no MongoDB
                transaction_data = {
                    "txid": txid,
                    "buy_address_account": buy_address_account,
                    "buy_name": buy_name,
                    "buy_idnumber": buy_idnumber,
                    "buy_type": buy_type,
                    "buy_email": buy_email,
                    "buy_description": description_buy,
                    "buy_asset_code": self.buy_asset_code,
                    "buy_amount": self.buy_amount,
                    "buy_address": self.address,
                    "pix_status": None,
                    "buy_card_name": card_name,
                    "credit_card_status": payment_intent.status,
                    "buy_status": "PENDENTE",
                    "buy_transaction_id": transaction_id,
                    "transaction_datetime": datetime.datetime.utcnow()
                }

                buys_collection.insert_one(transaction_data)

                print(f"Payment succeeded. Your bougth is in our account.")
                message = (
                    f"<br>"
                    f"Payment succeeded. Your bougth is in our account.<br><br"
                    f"<br>"
                )
                return message

            else:
                # Salvar transação no MongoDB
                transaction_data = {
                    "txid": self.txid,
                    "buy_address_account": buy_address_account,
                    "buy_name": buy_name,
                    "buy_idnumber": buy_idnumber,
                    "buy_type": buy_type,
                    "buy_email": buy_email,
                    "buy_description": description_buy,
                    "buy_asset_code": self.buy_asset_code,
                    "buy_amount": self.buy_amount,
                    "buy_address": self.address,
                    "pix_status": None,
                    "buy_card_name": card_name,
                    "credit_card_status": payment_intent.status,
                    "buy_status": "ERROR STRIPE PAYMENT",
                    "buy_transaction_id": transaction_id,
                    "transaction_datetime": datetime.datetime.utcnow()
                }

                buys_collection.insert_one(transaction_data)

                print(f"Payment succeeded. Your bougth is in our account.")
                message = (
                    f"<br>"
                    f"Payment is not succeeded. Your bougth is not in our account. Try again!<br><br"
                    f"<br>"
                )
                return message

        else:
            # Caso o status não seja 'ATIVA', você pode retornar outro código ou tratar o erro
            print(f"Please, activate your account. User does not exists in MongoDB")
            message = (
                f"<br>"
                f"Please, activate your account.<br>"
                f"You can activate your account filling the settings information<br>"
                f"<br>"
            )
            return message

        
