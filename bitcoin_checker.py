import secrets
import hashlib
import os
from mnemonic import Mnemonic
import ecdsa
from bitcoin import privtopub, pubtoaddr
import asyncio
import aiohttp
import json
import time
import signal
import random

# Global settings
address_counter = 0
continue_checking = True
output_file = "found_wallets.txt"
API_CALL_INTERVAL = 10
MAX_CONCURRENT_REQUESTS = 10000  # Adjust for API rate limits

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
    """Fetches the balance of a Bitcoin address using multiple APIs."""
    async with semaphore:
        try:
            # Blockcypher API
            url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance"
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("balance", 0)
        except Exception:
            pass

        try:
            # Blockstream API (fallback)
            url = f"https://blockstream.info/api/address/{address}"
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    balance = (
                        data.get("chain_stats", {}).get("funded_txo_sum", 0)
                        - data.get("chain_stats", {}).get("spent_txo_sum", 0)
                    )
                    return balance
        except Exception:
            return -1

    return -1  # Indicate no balance found or error


def save_wallet_to_file(mnemonic, private_key, address, balance):
    """Saves wallet details to a file."""
    with open(output_file, "a") as f:
        f.write("=" * 30 + "\n")
        f.write(f"Wallet #{address_counter} found!\n")
        f.write(f"Mnemonic: {mnemonic}\n")
        f.write(f"Private Key (Hex): {private_key.hex()}\n")
        f.write(f"Address: {address}\n")
        f.write(f"Balance: {balance} satoshis\n")
        f.write("=" * 30 + "\n")


def signal_handler(sig, frame):
    """Handles interrupt signals."""
    global continue_checking
    print("\nStopping the wallet checker...")
    continue_checking = False


async def check_wallet(session):
    """Generates and checks a single wallet."""
    global address_counter

    mnemonic = generate_bip39_seed()
    private_key = get_private_key_from_mnemonic(mnemonic)
    address = get_bitcoin_address(private_key)

    address_counter += 1

    if address_counter % API_CALL_INTERVAL == 0:
        balance = await fetch_balance(session, address)
        print(f"Checked Wallet #{address_counter}: {address} | Balance: {balance} satoshis")

        if balance > 0:
            print("Wallet with balance found! Saving details...")
            save_wallet_to_file(mnemonic, private_key, address, balance)


async def main():
    """Main function to run the wallet checker."""
    global address_counter

    signal.signal(signal.SIGINT, signal_handler)
    print("Press Ctrl+C to stop the script.")

    async with aiohttp.ClientSession() as session:
        tasks = []
        while continue_checking:
            if len(tasks) < MAX_CONCURRENT_REQUESTS:
                tasks.append(asyncio.create_task(check_wallet(session)))

            # Remove completed tasks
            tasks = [t for t in tasks if not t.done()]
            await asyncio.sleep(0.05)  # Slight delay to manage task scheduling

        # Wait for all remaining tasks to complete
        await asyncio.gather(*tasks)

    print("Wallet checker finished.")


if __name__ == "__main__":
    asyncio.run(main())
