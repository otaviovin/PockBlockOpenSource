# ========================
# Imports and Dependencies
# ========================

# Imports core classes for interacting with the Stellar network:
# - Keypair: for key generation and signing
# - Server: to connect to Horizon server (Stellar API)
# - Network: to define which network (testnet or public) is used
# - TransactionBuilder: for building and signing Stellar transactions
# - Asset: for working with custom or native assets
# - exceptions: general exception classes related to Stellar operations
from stellar_sdk import Keypair, Server, Network, TransactionBuilder, Asset, exceptions

# Specific exception class for invalid Stellar secret seeds
from stellar_sdk.exceptions import Ed25519SecretSeedInvalidError

# MongoDB client to connect and interact with a MongoDB database
from pymongo import MongoClient

# OS module to interact with the file system or environment
import os

# Loads environment variables from a .env file into the runtime environment
from dotenv import load_dotenv

# Provides accurate decimal arithmetic, particularly important in financial applications
# - ROUND_DOWN ensures values are truncated, not rounded up
from decimal import Decimal, ROUND_DOWN

# Utility for encoding/decoding Stellar keys (e.g., converting between public/secret keys and raw bytes)
from stellar_sdk import StrKey

# Load environment variables from .env file
load_dotenv()

GLOBAL_NETWORK = os.getenv("GLOBAL_NETWORK", "mainnet")
HORIZON_URL = os.getenv("SERVER_URL") # Server url

# MongoDB Configuration
mongo_client = MongoClient(os.getenv("MONGODB_URI"))
data_db_withdraw = mongo_client["withdrawpocketblock"]
settings_collection = data_db_withdraw["settings_value_fiat"]

class Transaction:
    """
    This class provides methods for handling Stellar transactions, including:
    - Checking if a trustline exists for a specific asset
    - Creating a trustline if necessary
    - Checking liquidity for a transaction
    - Executing transactions between different assets on the Stellar network.
    
    Attributes:
        network (str): The network type ('mainnet' or 'testnet').
        seed (str): The secret key used to sign transactions.
        sender_asset_code (str): The asset code of the sender's asset (e.g., 'XLM', 'USDC').
        asset_code (str): The asset code for the transaction (e.g., 'XLM', 'USDC').
        destination_account (str): The public key of the destination account.
        amount_sell (float): The amount to be sold.

    Methods:
        has_trustline(account_id, asset_code, issuer):
            Checks if a trustline exists for a given asset on the account.
        
        create_trustline(account_id, asset_code, issuer):
            Creates a trustline for a given asset on the account if it does not exist.
        
        check_liquidity(send_asset, dest_asset, send_amount):
            Checks if liquidity paths are available for a transaction.
        
        execute():
            Executes the transaction, transferring assets between accounts.
    """

    def __init__(self, network, keypair, seed, sender_asset_code, asset_code, destination_account, amount_sell):
        """
        Initializes the transaction object with the necessary parameters.

        Args:
            network (str): The network to use ('mainnet' or 'testnet').
            keypair (Keypair): The Keypair object of the sender.
            seed (str): The secret key of the sender.
            sender_asset_code (str): The asset code to be sent (e.g., 'XLM').
            asset_code (str): The asset code to be received (e.g., 'USDC').
            destination_account (str): The destination account address.
            amount_sell (float): The amount of the sender's asset to send.
        """
        self.network = network
        self.keypair = keypair
        self.seed = seed
        self.sender_asset_code = sender_asset_code
        self.asset_code = asset_code
        self.destination_account = destination_account
        self.amount_sell = amount_sell

        # Configure the Stellar network and Horizon URL
        self.horizon_url = HORIZON_URL
        self.network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE if self.network == 'testnet' else Network.PUBLIC_NETWORK_PASSPHRASE
        self.server = Server(horizon_url=self.horizon_url)

    def get_balance(self):
        """
        Fetches the balance of the specified asset from the Stellar trustline.

        Returns:
            float: The available balance of the asset, or 0 if not found.
        """
        
        # Determine the Horizon server URL based on the selected network
        server_url = HORIZON_URL
        
        try:
            
            server = Server(horizon_url=server_url) # Connect to Stellar's Horizon server
            account = server.accounts().account_id(self.keypair).call()
            asset_balance = "0" # Default asset balance

            # Loop through account balances to find the requested asset
            for balance in account["balances"]:
                # if (self.withdraw_asset_code == "XLM" and balance["asset_type"] == "native") or (balance.get("asset_code") == self.withdraw_asset_code):
                if (balance.get("asset_code") == self.sender_asset_code):    
                    asset_balance = float(balance["balance"])
                    return asset_balance  # Return balance immediately

            return asset_balance  # If asset is not found, return 0

        except Exception as e:
            return f"Error fetching Stellar balance: {str(e)}"

    def has_trustline(self, account_id, asset_code, issuer):
        """
        Checks if the specified account has a trustline for the given asset.

        Args:
            account_id (str): The public key of the account.
            asset_code (str): The asset code (e.g., 'XLM', 'USDC').
            issuer (str): The issuer of the asset.

        Returns:
            bool: True if the trustline exists, False otherwise.
        """
        try:
            account_id_clean = account_id.split("#")[0].strip()
            account = self.server.load_account(account_id_clean)

            # Checks for the trustline
            for balance in account.balances:
                if (
                    balance.get("asset_code") == asset_code and
                    balance.get("asset_issuer") == issuer and
                    balance.get("is_authorized", True) 
                ):
                    return True
                
            return False
        
        except Exception as e:
            return False

    def create_trustline(self, account_id, asset_code, issuer):
        """
        Creates a trustline for the specified asset if one does not exist.

        Args:
            account_id (str): The public key of the account.
            asset_code (str): The asset code to create the trustline for.
            issuer (str): The issuer of the asset.

        Returns:
            response: The response from the Stellar network after attempting to create the trustline.
        """
        try:
            secret_key = self.seed
            
            if not secret_key:
                raise ValueError("Secret key is not provided.")

            try:
                keypair = Keypair.from_secret(secret_key)
            except Ed25519SecretSeedInvalidError:
                raise ValueError("Invalid secret key.")

            public_key = keypair.public_key 
            # network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE
            network_passphrase = Network.PUBLIC_NETWORK_PASSPHRASE

            source_account = self.server.load_account(public_key)
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

            transaction.sign(keypair)
            response = self.server.submit_transaction(transaction)

            return response

        except Exception as e:
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
            paths = self.server.strict_send_paths(
                source_asset=send_asset,
                source_amount=str(send_amount),
                destination=[dest_asset]
            ).call()

            if len(paths['_embedded']['records']) > 0:
                return True
            
            else:
                return False
            
        except Exception as e:
            return False

    def execute(self):
        """
        Executes the transaction based on the provided parameters and network settings.

        This method performs the following actions:
        - Checks if the sender's account has the necessary trustline.
        - Creates a trustline if it doesn't exist.
        - Sends the specified amount of the asset from the sender's account to the destination account.
        
        Returns:
            str: A message with the transaction result.
        """
        try:
            secret_key = self.seed
            source_keypair = Keypair.from_secret(secret_key)
            sender_account_id = source_keypair.public_key
            sender_balance = self.get_balance()

            # if Decimal(current_balance) < Decimal(self.withdraw_amount):

            if Decimal(sender_balance) < Decimal(self.amount_sell):
                message = (f"<br>Error: Insufficient balance of {self.sender_asset_code} in the sender's account.<br>")
                return message

            if not secret_key:
                raise ValueError("Secret key is not provided.")

            try:
                keypair = Keypair.from_secret(secret_key)
                
            except Ed25519SecretSeedInvalidError:
                raise ValueError("Invalid secret key.")

            source_keypair = Keypair.from_secret(secret_key)
            source_account = self.server.load_account(account_id=source_keypair.public_key)
            destination_account = self.destination_account
            if destination_account:
                destination_account = destination_account
            amount_asset_sell = self.amount_sell

            settings_usd = settings_collection.find_one({"withdraw_type": "USD"})
            perc_withdraw_usd = settings_usd["fee"]
            value_usd = settings_usd["value"]
            float_perc_withdraw_usd = Decimal(perc_withdraw_usd)
            float_value_usd = Decimal(value_usd)

            settings_eur = settings_collection.find_one({"withdraw_type": "EUR"})
            perc_withdraw_eur = settings_eur["fee"]
            value_eur = settings_eur["value"]
            float_perc_withdraw_eur = Decimal(perc_withdraw_eur)
            float_value_eur = Decimal(value_eur)

            FEE_ADDRESS = os.getenv("FEE_ADDRESS")

            if self.sender_asset_code == 'USDC':
                send_asset = Asset("USDC", os.getenv("USDC_ADDRESS"))
            elif self.sender_asset_code == 'EURC':
                send_asset = Asset("EURC", os.getenv("EURC_ADDRESS"))
            else:
                message = (f"<br>Error: Sender asset invalid.<br>")
                return message

            if self.asset_code == 'USDC':
                asset = Asset("USDC", os.getenv("USDC_ADDRESS"))
            elif self.asset_code == 'EURC':
                asset = Asset("EURC", os.getenv("EURC_ADDRESS"))
            else:
                message = (f"<br>Error: Receiver asset invalid.<br>")
                return message

            liquidity_available = self.check_liquidity(send_asset, asset, self.amount_sell)

            if not liquidity_available:
                message = (f"<br>There is not enough liquidity to exchange {self.amount_sell} {self.sender_asset_code} for {self.asset_code}.<br>")
                return message


            has_trust = self.has_trustline(destination_account, self.asset_code, asset.issuer)
            has_trust_fee_address = self.has_trustline(FEE_ADDRESS, self.asset_code, asset.issuer)

            if not has_trust:
                trustline_response = self.create_trustline(destination_account, self.asset_code, asset.issuer)

                if trustline_response is None:
                    message = (f"<br>Error: Criation of trustline break for {self.asset_code}.<br>")
                    return message
                
            if not has_trust_fee_address:
                trustline_response_fee = self.create_trustline(FEE_ADDRESS, self.asset_code, asset.issuer)

                if trustline_response_fee is None:
                    message = (f"<br>Error: Criation of trustline break for {self.asset_code}.<br>")
                    return message
                        
            source_account = self.server.load_account(account_id=source_keypair.public_key)

            try:
                if self.sender_asset_code == self.asset_code:

                    if self.sender_asset_code == "USDC" and self.asset_code =="USDC":
                        asset = Asset("USDC", os.getenv("USDC_ADDRESS"))
                        amount_fee = ((Decimal(self.amount_sell)) * (float_value_usd / float_value_eur)) * float_perc_withdraw_usd
                        amount_fee_value = amount_fee.quantize(Decimal("0.000001"), rounding=ROUND_DOWN)

                    elif self.sender_asset_code == "EURC" and self.asset_code =="EURC":
                        asset = Asset("EURC", os.getenv("EURC_ADDRESS"))
                        amount_fee = ((Decimal(self.amount_sell)) * (float_value_eur / float_value_usd)) * float_perc_withdraw_eur
                        amount_fee_value = amount_fee.quantize(Decimal("0.000001"), rounding=ROUND_DOWN)                       

                    print (f"asset: {asset}")
                    print (f"amount_fee_value: {amount_fee_value}")
                    print (f"amount_asset_sell: {amount_asset_sell}")
                    
                    destination_account_clean = destination_account.split("#")[0].strip()
                    fee_address_clean = FEE_ADDRESS.split("#")[0].strip()

                    text_memo = f"tx {self.sender_asset_code} to {self.asset_code}"
                    transaction = (
                        TransactionBuilder(
                            source_account=source_account,
                            network_passphrase=self.network_passphrase,
                            base_fee=100,
                        )
                        .add_text_memo(text_memo)
                        .append_payment_op(
                            destination_account_clean,
                            asset, 
                            str(amount_asset_sell)
                        )
                        .append_payment_op(
                            fee_address_clean, 
                            asset, 
                            str(amount_fee_value)
                        )
                        .set_timeout(30)
                        .build()
                    )

                else:                    
                    if self.sender_asset_code == 'USDC' and self.asset_code == 'EURC':
                        amount_min = ((Decimal(self.amount_sell)) * (float_value_usd / float_value_eur))
                        amount_fee = ((Decimal(self.amount_sell)) * (float_value_usd / float_value_eur)) * float_perc_withdraw_usd
                        amount_min_value = amount_min.quantize(Decimal("0.000001"), rounding=ROUND_DOWN)
                        amount_fee_value = amount_fee.quantize(Decimal("0.000001"), rounding=ROUND_DOWN)
                    
                    elif self.sender_asset_code == 'EURC' and self.asset_code == 'USDC':
                        amount_min = ((Decimal(self.amount_sell)) * (float_value_eur / float_value_usd))
                        amount_fee = ((Decimal(self.amount_sell)) * (float_value_eur / float_value_usd)) * float_perc_withdraw_eur
                        amount_min_value = amount_min.quantize(Decimal("0.000001"), rounding=ROUND_DOWN)
                        amount_fee_value = amount_fee.quantize(Decimal("0.000001"), rounding=ROUND_DOWN)
                    
                    transaction = (
                        TransactionBuilder(
                            source_account=source_account,
                            network_passphrase=self.network_passphrase,
                            base_fee=100
                        )
                        .append_path_payment_strict_send_op(
                            destination=destination_account,
                            send_asset=send_asset,
                            send_amount=str(amount_asset_sell),
                            dest_asset=asset,
                            dest_min=str(amount_min_value),
                            path=[]
                        )
                        .append_payment_op(
                            FEE_ADDRESS, 
                            send_asset, 
                            str(amount_fee_value))
                        .set_timeout(30)
                        .build()
                    )
                
                transaction.sign(source_keypair)
                response = self.server.submit_transaction(transaction)
                
                message = (
                            f"<br><strong>From account:</strong> <br> {source_account} <br><br>"
                            f"<strong>To account:</strong> <br> {destination_account} <br><br>"
                            f"<strong>Network:</strong> <br> {self.horizon_url} - {self.network} <br><br>"
                            f"<strong>Send:</strong> <br> {str(amount_asset_sell)} {self.sender_asset_code} <br> from account {source_account} <br><br>"
                            f"<strong>Receive:</strong> <br> {str(amount_asset_sell)} {self.asset_code} <br> in account {destination_account} <br>"
                            # f"<strong>Transaction submitted successfully!</strong> <br> Response: {response}"
                        )
                return message
            
            except exceptions.BadRequestError as e:
                message = (f"<br>Bad request - check your transaction parameters.<br>")
                return message
                
        except Exception as e:
            message = (f"<br>Error: During transaction - check your transaction parameters.<br>") 
            return message
