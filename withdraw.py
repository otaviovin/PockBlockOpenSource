import datetime
import random
import string
from pymongo import MongoClient
from stellar_sdk import Server, Keypair, TransactionBuilder, Asset, Network, exceptions
from stellar_sdk.exceptions import Ed25519SecretSeedInvalidError
import os
from dotenv import load_dotenv
from decimal import Decimal, ROUND_DOWN

# Load environment variables from .env file
load_dotenv()

GLOBAL_NETWORK = os.getenv("GLOBAL_NETWORK", "mainnet")
HORIZON_URL = os.getenv("SERVER_URL") # Server url

# MongoDB Configuration
mongo_client = MongoClient(os.getenv("MONGODB_URI"))
data_db_withdraw = mongo_client["withdrawpocketblock"]
transactions_collection = data_db_withdraw["withdraws"]
settings_collection = data_db_withdraw["settings_value_fiat"]

def generate_buttons():
    return (
        f"<button id='closeNotificationBtn' onclick='closeNotification()'><i class='fas fa-times'></i> Fechar</button>"
        f"<button id='copyBtn' onclick='copyToClipboard()'><i class='fas fa-copy'></i> Copy</button>"
        f"<button id='shareBtn' onclick='shareNotification()'><i class='fas fa-share-alt'></i> Share</button>"
    )

class Withdraw:
    """
    A class to handle asset withdrawals and conversions to fiat using the Circle API.
    
    Attributes:
        network (str): The network type ('testnet' or 'mainnet').
        keypair (Keypair): The Stellar keypair associated with the account.
        seed (str): The secret seed for the Stellar account.
        withdraw_asset_code (str): The asset being withdrawn (e.g., 'XLM', 'USDC').
        withdraw_amount (float): The amount of the asset to be withdrawn.
        withdraw_fiat (str): The fiat currency for conversion.
    """

    def __init__(self, network, keypair, seed, withdraw_asset_code, withdraw_amount, withdraw_fiat):
        """
        Initializes the Withdraw object with user and transaction details.
        
        Args:
            network (str): The Stellar network ('testnet' or 'mainnet').
            keypair (Keypair): The Stellar keypair linked to the transaction.
            seed (str): The secret seed of the account.
            withdraw_asset_code (str): The asset code to be withdrawn.
            withdraw_amount (float): The amount to withdraw.
            withdraw_fiat (str): The fiat currency to convert the asset into.
        """
        self.network = network
        self.keypair = keypair
        self.seed = seed
        self.withdraw_asset_code = withdraw_asset_code
        self.withdraw_amount = withdraw_amount
        self.withdraw_fiat = withdraw_fiat

    def get_balance(self):
        """
        Fetches the balance of the specified asset from the Stellar trustline.

        Returns:
            float: The available balance of the asset, or 0 if not found.
        """
        
        # Determine the Horizon server URL based on the selected network
        server_url = HORIZON_URL
        
        try:
            # Connect to Stellar's Horizon server
            server = Server(horizon_url=server_url)
            account = server.accounts().account_id(self.keypair).call()
            
            print(account['balances'])  # Debugging statement

            # Default asset balance
            asset_balance = "0"

            # Loop through account balances to find the requested asset
            for balance in account["balances"]:
                # if (self.withdraw_asset_code == "XLM" and balance["asset_type"] == "native") or (balance.get("asset_code") == self.withdraw_asset_code):
                if (balance.get("asset_code") == self.withdraw_asset_code):    
                    print(f"Withdraw Amount: {self.withdraw_amount} {self.withdraw_asset_code}")
                    print(f"Available Balance: {balance['balance']} {self.withdraw_asset_code}")
                    asset_balance = float(balance["balance"])
                    return asset_balance  # Return balance immediately

            return asset_balance  # If asset is not found, return 0

        except Exception as e:
            print(f"Error fetching Stellar balance: {str(e)}")
            return f"Error fetching Stellar balance: {str(e)}"
    
    def has_trustline(self, account_id, asset_code, issuer):
        """
        Checks whether the given account has an existing trustline for a specific asset.

        Args:
            account_id (str): The public key of the account.
            asset_code (str): The asset code (e.g., 'XLM', 'USDC').
            issuer (str): The issuer of the asset.

        Returns:
            bool: True if a trustline exists, False otherwise.
        """
        try:
            # Configure the Stellar network and Horizon URL
            print("Connecting to Stellar server...")
            horizon_url = HORIZON_URL
            network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE if self.network == 'testnet' else Network.PUBLIC_NETWORK_PASSPHRASE
            
            server = Server(horizon_url=horizon_url)
            account = server.load_account(account_id)
            
            # Check if the trustline exists in the account's balances
            for balance in account.balances:
                if balance.get('asset_code') == asset_code and balance.get('asset_issuer') == issuer:
                    return True
            return False
        
        except Exception as e:
            print(f"Error checking trustline: {e}")
            return False
    
    def create_trustline(self, account_id, asset_code, issuer):
        """
        Creates a trustline for the given asset if it does not exist.

        Args:
            account_id (str): The Stellar public key of the account.
            asset_code (str): The asset code for the trustline.
            issuer (str): The issuing account of the asset.

        Returns:
            dict: The response from Stellar if the trustline creation succeeds.
        """
        try:
            if not self.seed:
                raise ValueError("Secret key is required.")
            
            # Validate the secret key
            try:
                keypair = Keypair.from_secret(self.seed)
            except Ed25519SecretSeedInvalidError:
                raise ValueError("Invalid secret key.")
            
            public_key = keypair.public_key
            self.horizon_url = HORIZON_URL # Set the network's Horizon URL
            server = Server(horizon_url=HORIZON_URL)
            network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE if self.network == 'testnet' else Network.PUBLIC_NETWORK_PASSPHRASE
            source_account = server.load_account(public_key) # Load the Stellar account and prepare the trustline transaction
            asset = Asset(asset_code, issuer)

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
            
            # Sign and submit the transaction
            transaction.sign(keypair)
            response = server.submit_transaction(transaction)
            return response
        except Exception as e:
            print(f"Error creating trustline: {e}")
            return None
    
    def check_liquidity(self, send_asset, dest_asset, send_amount):
        """
        Checks if liquidity paths are available for a specific transaction.

        Args:
            send_asset (Asset): The asset being sent.
            dest_asset (Asset): The asset to be received.
            send_amount (float): The amount of the sending asset.

        Returns:
            bool: True if liquidity paths exist, False otherwise.
        """
        try:
            horizon_url = HORIZON_URL # Server url
            server = Server(horizon_url=horizon_url)
            paths = server.strict_send_paths(
                source_asset=send_asset,
                source_amount=str(send_amount),
                destination=[dest_asset]
            ).call()

            if len(paths['_embedded']['records']) > 0:
                return True
            else:
                return False
        except Exception as e:
            print(f"Error checking liquidity: {e}")
            return False
        
    def withdraw_transaction(self, withdraw_amount, withdraw_name, withdraw_asset, withdraw_idnumber, description_withdraw, withdraw_type, withdraw_bank, withdraw_bank_ag, withdraw_bank_cc, withdraw_country, withdraw_pix, withdraw_fiat):
        """
        Executes the transaction based on the provided parameters and network settings.

        This method performs the following actions:
        - Checks if the sender's account has the necessary trustline.
        - Creates a trustline if it doesn't exist.
        - Sends the specified amount of the asset from the sender's account to the destination account.
        
        Returns:
            str: A message with the transaction result.
        """

        current_balance = self.get_balance()
        if Decimal(current_balance) < Decimal(self.withdraw_amount):
            return f"Erro: Saldo insuficiente. Saldo atual: {current_balance}, valor solicitado: {self.withdraw_amount}"

        try:
            horizon_url = HORIZON_URL
            network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE if self.network == 'testnet' else Network.PUBLIC_NETWORK_PASSPHRASE
            secret_key = self.seed

            if not secret_key:
                raise ValueError("Secret key is not provided.")

            source_keypair = Keypair.from_secret(secret_key)
            server = Server(horizon_url=horizon_url)
            source_account = server.load_account(account_id=source_keypair.public_key)

            # Consulta para encontrar o 'withdraw_account' pela 'withdraw_asset'
            accounts_collection = mongo_client["withdrawpocketblock"]["accounts_withdraw"]
            destination_account_data = accounts_collection.find_one({"withdraw_asset": self.withdraw_asset_code})

            if not destination_account_data:
                message = (
                    f"<br>"
                    f"Erro: Destination account for asset {self.withdraw_asset_code} not found in database.<br>"
                    f"<br>"
                    + generate_buttons()
                )
                return message

            # Atribuindo a 'withdraw_account' da conta de destino encontrada
            destination_account = destination_account_data["withdraw_account"]           
                        
            if self.withdraw_asset_code == 'USDC' or self.withdraw_asset_code == 'EURC':

                if self.withdraw_asset_code == "USDC":
                    settings = settings_collection.find_one({"withdraw_type": "USD"})
                elif self.withdraw_asset_code == 'EURC':
                    settings = settings_collection.find_one({"withdraw_type": "EUR"})
                else:
                    print(f"Error defining settings")
                    
                print(f"Settings: {settings}")

                try:
                    fee_withdraw = settings["fee"]
                    print(f"fee percentage found: {fee_withdraw}%")
                    withdraw_amount = Decimal(self.withdraw_amount) + (Decimal(self.withdraw_amount) * Decimal(fee_withdraw))
                    withdraw_amount_value = withdraw_amount.quantize(Decimal("0.01"), rounding=ROUND_DOWN)
                    withdraw_fee = Decimal(self.withdraw_amount) * Decimal(fee_withdraw)
                    print(f"New value with fee applied: {withdraw_amount_value}")
                    print(f"Fee value : {withdraw_fee}")

                except (ValueError, TypeError) as e:
                    print(f"Error applying fee_withdraw: {e}")
                
                # Definir o sender e o ativo com base na escolha do usuário
                if self.withdraw_asset_code == 'USDC':
                    send_asset = Asset("USDC", os.getenv("USDC_ADDRESS"))
                    asset = Asset("USDC", os.getenv("USDC_ADDRESS"))
                elif self.withdraw_asset_code == 'EURC':
                    send_asset = Asset("EURC", os.getenv("EURC_ADDRESS"))
                    asset = Asset("EURC", os.getenv("EURC_ADDRESS"))
                else:
                    message = (
                        f"<br>"
                        "Error: Sender asset invalid.<br>"
                        f"<br>"
                        + generate_buttons()
                        )
                    return message

                # Verificar se a conta tem a trustline
                has_trust = self.has_trustline(source_account, self.withdraw_asset_code, asset.issuer)

                if not has_trust:
                    print(f"Trustline não encontrada. Criando trustline para {self.withdraw_asset_code}...")
                    trustline_response = self.create_trustline(destination_account, self.withdraw_asset_code, asset.issuer)

                    if trustline_response is None:
                        message = (
                            f"<br>"
                            f"Criation of trustline break for {self.withdraw_asset_code}. Quiting.<br>"
                            f"<br>"
                            + generate_buttons()
                            )
                        return message
                    print(f"Trustline created for {self.withdraw_asset_code} succefully.")

                print("Proceeding with the transaction...")

                source_account = server.load_account(account_id=source_keypair.public_key)

                try:

                    withdraw_amount = withdraw_amount_value
                    # Obtém saldo na Stellar antes de permitir o saque
                    balance = self.get_balance()
                    balance = Decimal(balance)
                    print(f"Saldo disponível de {self.withdraw_asset_code}: {balance}")

                    min_length = 26
                    max_length = 35

                    # Pegar os 10 primeiros caracteres da chave pública
                    txid_base = self.keypair[:10]
                    print(f"txid_base: {txid_base}")

                    # Definir tamanho total aleatório dentro do intervalo permitido
                    total_length = random.randint(min_length, max_length)
                    print(f"total_length: {total_length}")

                    # Gerar caracteres aleatórios para completar o restante do txid
                    random_chars = ''.join(random.choices(string.ascii_letters + string.digits, k=total_length - len(txid_base)))
                    print(f"random_chars: {random_chars}")

                    self.txid = txid_base + random_chars
                    print(f"txid: {self.txid}")

                    transaction = (
                        TransactionBuilder(
                            source_account=source_account,
                            network_passphrase=network_passphrase,
                            base_fee=100
                        )
                        .append_path_payment_strict_send_op(
                            destination=destination_account,
                            send_asset=send_asset,
                            send_amount=str(withdraw_amount),
                            dest_asset=asset,
                            dest_min=str(withdraw_amount),
                            path=[]
                        )
                        .add_text_memo(self.txid[:16])
                        .set_timeout(30)
                        .build()
                    )

                    transaction.sign(source_keypair)
                    response = server.submit_transaction(transaction)
                    print(response)
                    
                    try:
                        # Verifica se a transação foi bem-sucedida antes de salvar no MongoDB
                        if response and response.get("successful", False):
                            print("Transação realizada com sucesso! Salvando no MongoDB...")
                            withdraw_fiat = withdraw_asset[:3]
                            # Salvar transação no MongoDB
                            withdraw_data = {
                                "txid": self.txid,
                                "withdraw_address": self.keypair,
                                "withdraw_name": withdraw_name,
                                "withdraw_idnumber": withdraw_idnumber,
                                "withdraw_type": withdraw_type,
                                "withdraw_description": description_withdraw,
                                "withdraw_asset": withdraw_asset,
                                "withdraw_fiat": withdraw_fiat,
                                "withdraw_amount": str(withdraw_amount),
                                "withdraw_fee": str(withdraw_fee),
                                "withdraw_pix": withdraw_pix,
                                "withdraw_bank": withdraw_bank,
                                "withdraw_bank_ag": withdraw_bank_ag,
                                "withdraw_bank_cc": withdraw_bank_cc,
                                "withdraw_country": withdraw_country,
                                "withdraw_response_blockchain": response,
                                "withdraw_status": "PENDENTE",
                                "transaction_datetime": datetime.datetime.utcnow(),
                                "withdraw_envioid": None,
                                "withdraw_e2eid": None,
                                "updated_idenvio_at": datetime.datetime.utcnow()
                            }

                            try:
                                result = transactions_collection.insert_one(withdraw_data)
                                print("Insert acknowledged:", result.acknowledged)
                                print("Inserted ID:", result.inserted_id)
                                
                            except Exception as e:
                                import traceback
                                print("Erro ao inserir no MongoDB:")
                                print(traceback.format_exc())  # imprime a stack trace completa

                            if result.acknowledged:
                                if withdraw_type == 'pix':
                                    print("Message PIX")
                                    message = (
                                        f"<br>"
                                        f"<strong>Withdraw from account:</strong> <br> {self.keypair} <br>"
                                        f"<strong>Saque solicitado via PIX:</strong> <br>"
                                        f"<strong>Nome:</strong> <br>{withdraw_name} <br>"
                                        f"<strong>ID Number:</strong> <br>{withdraw_idnumber} <br>"
                                        f"<strong>Received:</strong> <br> {str(self.withdraw_amount)} {self.withdraw_asset_code} <br>"
                                        f"<strong>Fee:</strong> <br> {str(withdraw_fee)} {self.withdraw_asset_code} <br>"
                                        f"<strong>PIX sent to key:</strong> <br> {str(withdraw_pix)} <br>"
                                        f"<strong>Descrição:</strong> <br>{description_withdraw} <br>"
                                        f"<br>"
                                        + generate_buttons()
                                    )
                                elif withdraw_type == 'bank_transfer':
                                    message = (
                                        f"<br>"
                                        f"<strong>Withdraw from account:</strong> <br> {self.keypair} <br>"
                                        f"<strong>Saque solicitado via Transferência Bancária:</strong> <br>"
                                        f"<strong>Nome:</strong> <br>{withdraw_name} <br>"
                                        f"<strong>ID Number:</strong> <br>{withdraw_idnumber} <br>"
                                        f"<strong>Received:</strong> <br> {str(self.withdraw_amount)} {self.withdraw_asset_code} <br>"
                                        f"<strong>Fee:</strong> <br> {str(withdraw_fee)} {self.withdraw_asset_code} <br>"
                                        f"<strong>Bank:</strong> <br> {str(withdraw_bank)} <br>"
                                        f"<strong>AG:</strong> <br> {str(withdraw_bank_ag)} <br>"
                                        f"<strong>CC:</strong> <br> {str(withdraw_bank_cc)} <br>"
                                        f"<strong>CC:</strong> <br> {str(withdraw_country)} <br>"
                                        f"<strong>Descrição:</strong> <br>{description_withdraw} <br>"
                                        f"<br>"
                                        + generate_buttons()
                                    )
                                else:
                                    message = (
                                        f"<br>"
                                        "Invalid withdrawal type.<br>"
                                        f"<br>"
                                        + generate_buttons()
                                    )
                                return message
                            
                            else:
                                message = (
                                    f"<br>"
                                    "Error saving data<br>"
                                    f"<br>"
                                    + generate_buttons()
                                )
                                return message
                        
                        else:
                            message = (
                                f"Transaction was not confirmed: {response}"
                            )
                            return message
                    
                    except Exception as e:
                        message = (
                            f"<br>"
                            f"Error processing transaction: {str(e)}<br>"
                            f"<br>"
                            + generate_buttons()
                        )
                        return message

                except exceptions.BadRequestError as e:
                    print("Error: Bad request - check your transaction parameters.", e)
                    message = (
                        f"<br>"
                        f"Check your transaction parameters.<br>"
                        f"<br>"
                        + generate_buttons()
                        )
                    return message
                
        except Exception as e:
            print("An unexpected error occurred:", e)
            message = (
                f"<br>"
                "Error during transaction.<br>" 
                f"<br>"
                + generate_buttons()
            )
            return message
