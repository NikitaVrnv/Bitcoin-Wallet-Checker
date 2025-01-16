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

# Global counter for number of addresses checked
address_counter = 0
continue_checking = True
output_file = "found_wallets.txt"  # Name of output file
API_CALL_INTERVAL = 10  # Check balance every n wallets
MAX_CONCURRENT_REQUESTS = 5000  # Increased concurrent requests


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
    """Gets Bitcoin address from the private key"""
    public_key = privtopub(private_key.hex())
    address = pubtoaddr(public_key)
    return address

async def fetch_balance_blockcypher(session, address):
    """Fetches the balance of the Bitcoin address using blockcypher API."""
    try:
      url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance"
      async with session.get(url) as response:
        response.raise_for_status()
        data = await response.json()
        return data.get('balance', 0)
    except aiohttp.ClientError:
        return -1  # Indicate an error

async def fetch_balance_blockstream(session, address):
    """Fetches the balance of the Bitcoin address using Blockstream API."""
    try:
      url = f"https://blockstream.info/api/address/{address}"
      async with session.get(url) as response:
        response.raise_for_status()
        data = await response.json()
        balance = data.get('chain_stats', {}).get('funded_txo_sum', 0) - data.get('chain_stats', {}).get('spent_txo_sum', 0)
        return balance
    except aiohttp.ClientError:
        return -1

async def fetch_address_balance(session, address):
  """Fetches the balance of a Bitcoin address using Blockcypher and Blockstream as a fallback."""
  balance = await fetch_balance_blockcypher(session, address)
  if balance == -1:
      balance = await fetch_balance_blockstream(session, address)
  return balance

def save_wallet_to_file(mnemonic, private_key, address, balance):
    """Saves wallet details to a file."""
    try:
        with open(output_file, "a") as f:
            f.write("=" * 30 + "\n")
            f.write(f"Wallet found at #{address_counter}!\n")
            f.write(f"Mnemonic: {mnemonic}\n")
            f.write(f"Private Key (Hex): {private_key.hex()}\n")
            f.write(f"Address: {address}\n")
            f.write(f"Balance: {balance} satoshis\n")
            f.write("=" * 30 + "\n")
    except Exception as e:
        print(f"Error saving wallet details to file: {e}")

def signal_handler(sig, frame):
    global continue_checking
    print('\nStopping the wallet checker...')
    continue_checking = False


async def main():
    global address_counter
    signal.signal(signal.SIGINT, signal_handler)  # Set the signal handler
    print("Press Ctrl+C to stop the script.")

    async with aiohttp.ClientSession() as session:
      while continue_checking:
        mnemonic = generate_bip39_seed()
        private_key = get_private_key_from_mnemonic(mnemonic)
        address = get_bitcoin_address(private_key)

        address_counter += 1

        balance = 0
        if address_counter % API_CALL_INTERVAL == 0:
             balance = await fetch_address_balance(session, address)
             print(f"Wallet #{address_counter}")
             print(f"Mnemonic: {mnemonic}")
             print(f"Private Key (Hex): {private_key.hex()}")
             print(f"Address: {address}")
             print(f"Balance: {balance} satoshis")
             if balance > 0:
                print("Saving to file...")
                save_wallet_to_file(mnemonic, private_key, address, balance)
             print("-" * 30)
        await asyncio.sleep(0.1) # Respect rate limiting

      print("Wallet checker finished")

if __name__ == "__main__":
    asyncio.run(main())
