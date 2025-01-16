import secrets
import hashlib
from mnemonic import Mnemonic
from bitcoin import privtopub, pubtoaddr
import asyncio
import aiohttp
import time
import signal
import logging
import sys

# Global settings
ADDRESS_COUNTER = 0
CONTINUE_CHECKING = True
OUTPUT_FILE = "found_wallets.txt"
API_CALL_INTERVAL = 10
MAX_CONCURRENT_REQUESTS = 1000  # Reduced for testing; adjust as needed
API_BASE_URL = "https://blockstream.info/api"
RETRY_COUNT = 3
RETRY_DELAY = 1  # Initial retry delay in seconds

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


# Semaphore for controlling concurrency
semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)


def generate_bip39_seed():
    """Generates a random BIP39 mnemonic seed phrase."""
    mnemo = Mnemonic("english")
    entropy = secrets.token_bytes(16)
    mnemonic = mnemo.to_mnemonic(entropy)
    return mnemonic


def get_private_key_from_mnemonic(mnemonic):
    """Generates a private key from a mnemonic using the standard BIP32 path."""
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic)
    private_key = hashlib.sha256(seed).digest()
    return private_key


def get_bitcoin_address(private_key):
    """Gets Bitcoin address from the private key."""
    public_key = privtopub(private_key.hex())
    address = pubtoaddr(public_key)
    return address


async def fetch_balance(session, address):
    """Fetches the balance of a Bitcoin address using Blockstream API with retry logic."""
    url = f"{API_BASE_URL}/address/{address}"
    retry_delay = RETRY_DELAY
    for attempt in range(RETRY_COUNT):
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    balance = (
                        data.get("chain_stats", {}).get("funded_txo_sum", 0)
                        - data.get("chain_stats", {}).get("spent_txo_sum", 0)
                    )
                    return balance
                elif response.status == 429:
                     retry_after = int(response.headers.get("Retry-After", retry_delay))
                     logger.warning(
                        f"Rate limited for {address}, retrying in {retry_after} seconds (attempt {attempt + 1}/{RETRY_COUNT})"
                    )
                     await asyncio.sleep(retry_after)
                     retry_delay *= 2
                elif response.status >= 500:  # Server Error
                    logger.warning(
                        f"Server error {response.status} while getting balance for {address} (attempt {attempt + 1}/{RETRY_COUNT})"
                    )
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2
                elif response.status == 404: # Address not found
                    return 0 # Address has no balance.
                else:
                     logger.error(f"API error {response.status} for {address}, not retrying.")
                     return None # API error
        except aiohttp.ClientError as e:
            logger.error(f"Client error while fetching {address}: {e}")
            await asyncio.sleep(retry_delay)
            retry_delay *= 2
        except Exception as e:
            logger.error(f"Exception while fetching {address}: {e}")
            await asyncio.sleep(retry_delay)
            retry_delay *= 2

    logger.error(f"Max retries reached for {address}, giving up.")
    return None # API error or maximum retries


def save_wallet_to_file(mnemonic, private_key, address, balance):
    """Saves wallet details to a file."""
    global ADDRESS_COUNTER
    with open(OUTPUT_FILE, "a") as f:
        f.write("=" * 30 + "\n")
        f.write(f"Wallet #{ADDRESS_COUNTER} found!\n")
        f.write(f"Mnemonic: {mnemonic}\n")
        f.write(f"Private Key (Hex): {private_key.hex()}\n")
        f.write(f"Address: {address}\n")
        f.write(f"Balance: {balance} satoshis\n")
        f.write("=" * 30 + "\n")


def signal_handler(sig, frame):
    """Handles interrupt signals."""
    global CONTINUE_CHECKING
    logger.info("Stopping the wallet checker...")
    CONTINUE_CHECKING = False


async def check_wallet(session):
    """Generates and checks a single wallet."""
    global ADDRESS_COUNTER

    mnemonic = generate_bip39_seed()
    private_key = get_private_key_from_mnemonic(mnemonic)
    address = get_bitcoin_address(private_key)

    ADDRESS_COUNTER += 1

    if ADDRESS_COUNTER % API_CALL_INTERVAL == 0:
        async with semaphore:  # Throttle the API calls
            balance = await fetch_balance(session, address)
            if balance is None:
                logger.warning(f"Checked Wallet #{ADDRESS_COUNTER}: {address} | Balance: API error")
            else:
                logger.info(f"Checked Wallet #{ADDRESS_COUNTER}: {address} | Balance: {balance} satoshis")
                if balance > 0:
                   logger.info("Wallet with balance found! Saving details...")
                   save_wallet_to_file(mnemonic, private_key, address, balance)


async def main():
    """Main function to run the wallet checker."""
    global ADDRESS_COUNTER, CONTINUE_CHECKING

    signal.signal(signal.SIGINT, signal_handler)
    logger.info("Press Ctrl+C to stop the script.")

    async with aiohttp.ClientSession() as session:
        tasks = []
        while CONTINUE_CHECKING:
            if len(tasks) < MAX_CONCURRENT_REQUESTS:
                tasks.append(asyncio.create_task(check_wallet(session)))

            # Remove completed tasks
            tasks = [t for t in tasks if not t.done()]
            await asyncio.sleep(0.05)  # Slight delay to manage task scheduling

        # Wait for all remaining tasks to complete
        await asyncio.gather(*tasks)

    logger.info("Wallet checker finished.")


if __name__ == "__main__":
    asyncio.run(main())
