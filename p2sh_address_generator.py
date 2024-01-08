from sys import exit
from os import system, name
from base58check import b58encode
from bitcoinutils.setup import setup
from bitcoinutils.keys import PublicKey
from bitcoinutils.script import Script
from bitcoin.core import Hash160
from binascii import unhexlify
from hashlib import sha256
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from bitcoinlib import keys
from getpass import getpass


def main():
    #
    # This script creates a P2SH address setting an absolute locktime using CHECKLOCKTIMEVERIFY and P2PKH unlocking script
    #
    
    # Setup the network
    setup('testnet')

    while True:
        try:
            rpc_connection = rpc_connect()
            # Make an RPC call to the local bitcoin node to test the connection
            current_block = rpc_connection.getblockcount()
        except JSONRPCException:
            input("\n\nUnable to login with given credentials. Try again.\n\n\nHit Enter to continue...")
        except KeyboardInterrupt:
            exit()
        else:
            break



    #
    # TASK: accept a public key for the P2PKH part of the redeem script
    #
    while True:
        displaybanner()
        try:
            pk = keys.Key(input("Enter Public key: ")).public_hex
            public_key = PublicKey.from_hex(pk)
        except keys.BKeyError:
            input("\n\n\n\nERROR! Unrecognised Key format. Try Again.\n\nPress Enter to continue....")
            continue
        else:
            break



    #
    # Enter an absolute locktime to spend the transaction (expressed in block height)
    #
    # Verify that the absolute locktime entered is a valid number and < 500 million
    #
    while True:
        displaybanner()
        try:
            locktime = input(
                "Set an absolute locktime to spend the transaction (denoted in block height).\n\nLocktime [{}]: ".format(
                    current_block))
            if locktime == "":
                locktime = current_block
                break
            if locktime.isdigit():
                if int(locktime) < 500000000:
                    break
                else:
                    input("\n\n\nLocktime must be < 500,000,000. Press Enter to continue...")
            else:
                    input("\n\n\nLocktime must be an integer. Press Enter to continue...")
        except KeyboardInterrupt:
            exit()




    # Create redeem script to unlock P2SH ScriptSig
    redeem_script = Script([int(locktime), 'OP_CHECKLOCKTIMEVERIFY', 'OP_DROP', 'OP_DUP', 'OP_HASH160', public_key.to_hash160(), \
                            'OP_EQUALVERIFY', 'OP_CHECKSIG'])

    redeem_script_hash = Hash160(redeem_script.to_bytes()).hex()

    # Add the p2sh version prefix 0xc4 to script hash
    data = 'c4' + redeem_script_hash

    # Hash the data twice using sha265
    dataHash = sha256(sha256(unhexlify(data)).digest()).hexdigest()

    # Take the last 8 bytes in the data hash to use as a checksum
    checksum = dataHash[:8]

    # Use base35check encoding to generate the p2sh address
    address = b58encode(unhexlify(data + checksum)).decode()

    displaybanner()
    print("P2SH Address: {}\n\n\n\n".format(address))


def displaybanner():
    clearscreen()
    print("*"*55)
    print("*{:53}*".format(" "))
    print("*            BLOCK-521 Assignment - Script 1          *")
    print("*{:53}*".format(" "))
    print("*        Bitcoin Testnet P2SH address generator       *")
    print("*{:53}*".format(" "))
    print("*"*55, "\n\n\n")


def clearscreen():
    if name == 'nt': system('cls')
    else: system('clear')


def rpc_connect():
    # clear screen and display banner
    displaybanner()

    # Establish RPC connection to local bitcoin node on port 18332
    # Request login credentials from user
    user = input("Establishing connection to localhost on port 18332\n\nUsername: ")
    pw = getpass(prompt="Password: ", stream=None)
    return AuthServiceProxy("http://%s:%s@localhost:18332" % (user, pw), timeout=3600)


if __name__ == "__main__":
    exit(main())

