import bitcoinutils.setup as setup
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from bitcoinutils.keys import PrivateKey, P2shAddress, P2pkhAddress
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, Locktime
from tabulate import tabulate
from bitcoinutils.utils import to_satoshis
from bitcoinutils.constants import SIGHASH_ALL
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH
from os import system, name
from sys import exit
from getpass import getpass
from bitcoinlib import keys
from time import sleep
import subprocess


def main():
    # declare variables
    balance = 0
    script_evaluation = True

    setup.setup('testnet')



    #
    # Enter an absolute locktime to spend the transaction (expressed in block height)
    #
    while True:
        try:
            rpc_connection = rpc_connect()
            # Make an RPC call to the local bitcoin node to test the connection
            current_block = rpc_connection.getblockcount()
        except JSONRPCException:
            input("\n\n\nUnable to login with given credentials. Try again.\n\nPress any key to continue....")
        except KeyboardInterrupt:
            exit()
        else:
            break



    #
    # TASK: Enter an private key
    #
    while True:
        displaybanner()
        try:
            pk = keys.Key(input("Enter Private key: "), network=setup.get_network())
            private_key = PrivateKey.from_wif(pk.wif())
            public_key = private_key.get_public_key()
        except keys.BKeyError:
            input("\n\n\n\nERROR! Unrecognised Key format. Try Again.\n\nPress any key to continue....")
            continue
        except KeyboardInterrupt:
            exit()
        else:
            break


    # Verify that the absolute locktime entered is a valid number and < 500 million
    while True:
        displaybanner()
        try:
            locktime = input(
                "Set an absolute locktime to spend the transaction (denoted in block height).\n\nLocktime [{}]: ".format(
                    current_block))
            if locktime == "":
                blockheight = Locktime(current_block)
                break
            if locktime.isdigit():
                if int(locktime) < 500000000:
                    blockheight = Locktime(int(locktime))
                    break
                else:
                    input("\n\n\nLocktime must be < 500,000,000. \n\nPress any key to continue....")
            else:
                input("\n\n\nLocktime must be an integer. \n\nPress any key to continue....")
        except KeyboardInterrupt:
            exit()

    # Create the P2SH redeem Script
    redeem_script = Script(
        [blockheight.value, 'OP_CHECKLOCKTIMEVERIFY', 'OP_DROP', 'OP_DUP', 'OP_HASH160', public_key.to_hash160(),
         'OP_EQUALVERIFY', 'OP_CHECKSIG'])



    #
    # TASK: accept a P2SH address to get the funds from
    #
    # Verify P2SH address entered is the same aas the P2SH address generated above
    #
    p2sh_address = P2shAddress.from_script(redeem_script).to_string()
    p2sh_scriptPubKey = redeem_script.to_p2sh_script_pub_key()

    while True:
        displaybanner()
        try:
            p2sh_entered = input("P2SH address to spend [{}]: ".format(p2sh_address))
            if p2sh_entered == "" or p2sh_entered == p2sh_address:
                break
            elif keys.Address.parse(p2sh_entered).script_type == 'p2sh':
                 p2sh_address = P2shAddress(p2sh_entered).to_string()
                 break
            else:
                input("\n\n\nERROR: P2SH address invalid format. Try again.\n\nPress any key to continue....")
        except ValueError:
            input("\n\n\nInput Error. Try again.\n\nPress any key to continue....")
        except KeyboardInterrupt:
            exit()



    #
    # TASK: Check if the P2SH address has any UTXOs to get funds from
    #
    displaybanner()

    # Get a list of unspent transactions
    unspent_transactions = rpc_connection.listunspent()

    # Filter unspent_transactions list to only include the p2sh address
    p2sh_unspent_transactions = [_ for _ in unspent_transactions if _.get('address') == p2sh_address]

    # If the list is empty, the local bitcoin nodes wallet may not have the p2sh address and will need to be imported
    if len(p2sh_unspent_transactions) == 0:
        try:
            select = input(
                "\nImport P2SH address {} into wallet?\n\n\n"
                "\nWARNING: This call can take over an hour to complete, during that time, other rpc calls"
                "\nmay report that the imported address exists but related transactions are still missing,"
                "\nleading to temporarily incorrect balances and unspent outputs until rescan completes."
                "\n\n\n\nImport address ([y]/n])? ".format(p2sh_address))
            if select.lower() == 'y' or select.lower() == 'yes' or select == "":
                try:
                    passphrase = getpass(prompt="\n\nUnlocking wallet. Please enter the wallet passphrase: ")
                    rpc_connection.walletpassphrase(passphrase, 2)
                    command = ["bitcoin-cli", "importaddress", p2sh_address, "false"]
                    process = subprocess.Popen(command)
                    while True:
                        print('.', end='', flush=True)
                        if process.poll() is None:
                            sleep(1)
                        else:
                            input("\n\nRescan Complete. Press Enter to continue....")
                            break
                except BrokenPipeError:
                    print("\n\n\nERROR: Connection Timed Out")
            elif select.lower() == 'n' or select.lower() == 'no':
                input("\n\n\nCannot lookup transactions history on local bitcoin node.\n\nPress any key to exit....")
                exit()
            else:
                input("\n\nInput Error. Enter 'y' or 'n'.\n\nPress any key to continue.... ")
        except KeyboardInterrupt:
            exit()



    #
    # TASK: set fee to transaction block size in bytes * min fee
    #
    # Each transaction contains
    # 1. version number - 4 bytes
    # 2. n input's consisting of - 171 bytes
    #    a) signature & sighash - 72 bytes
    #    b) public key - 33 bytes
    #    c) redeem script - calculated to be 30 bytes
    #    d) TxID of unspent UTXO - 32 bytes
    #    e) Index Number of UTXO - 4 bytes
    # 3. output consisting of - 32
    #    a) amount - 8 bytes
    #    b) P2pkh scriptPubKey - 25 bytes
    # 4. locktime - 4 bytes
    #
    mempoolinfo = rpc_connection.getmempoolinfo()
    fee_per_byte = mempoolinfo.get('minrelaytxfee') / 1024

    fee = fee_per_byte * (4 + (len(unspent_transactions) * (72 + 33 + len(redeem_script.to_bytes()) + 32 + 4)) + 32 + 4)

    txlist = [[i.get("txid"), i.get("amount")] for i in p2sh_unspent_transactions]

    # Calculate unspent funds available
    for _ in p2sh_unspent_transactions:
        balance += _.get("amount")



    #
    # TASK: accept a P2PKH address to send the funds to
    #
    while True:
        displaybanner()
        displaybalance(balance, txlist)
        try:
            p2pkh_address = P2pkhAddress(input("\n\n\nP2pkh address to send {} btc to (Fee {}): ".format(balance-fee, fee)))
        except(ValueError):
            input("\n\n\nERROR: P2PKH key invalid. Try again.\n\nPress any key to continue....")
        except KeyboardInterrupt:
            exit()
        else:
            break



    #
    # TASK: send all funds that the P2SH address received to the P2PKH address provided
    #
    # Set the nSequence number to 0xfffffffe to activate the time lock feature
    # To spend transaction now, set nlocktime to the next block to be mined
    #
    txin = [TxInput(tx.get("txid"), tx.get("vout"), script_sig=p2sh_scriptPubKey, sequence='FFFFFFFE') for tx in
            p2sh_unspent_transactions]

    txout = TxOutput(to_satoshis(balance - fee), p2pkh_address.to_script_pub_key())

    blockheight.value += 1
    tx = Transaction(txin, [txout], locktime=blockheight.for_transaction())



    #
    # TASK: Display raw unsigned transaction
    #
    displaybanner()
    print("\n\nRaw unsigned transaction:\n" + tx.serialize())



    #
    # Sign each input
    #
    # Generate a signatures for each input and update the transaction with the signatures
    #
    tx_signature = [private_key.sign_input(tx, _, redeem_script, sighash=SIGHASH_ALL) for _ in range(len(txlist))]

    for _ in range(len(txlist)):
        txin[_].script_sig = Script([tx_signature[_], public_key.to_hex(), redeem_script.to_hex()])



    #
    # TASK: Display the raw signed transaction
    #
    print("\n\nRaw signed transaction:\n" + tx.serialize())
    tx_decoded = rpc_connection.decoderawtransaction(tx.serialize())



    #
    # TASK: Display the transaction ID
    #
    print("\n\nTransaction ID: \n{}".format(tx.get_txid()))



    #
    # TODO: There is an issue evaluating the bitcoin script calling the VerifyScript method which I haven't resolved yet.
    #
    # TASK: verify that the transaction is valid and will be accepted by the Bitcoin nodes
    #
    for i,t in enumerate(txin):
        try:
            VerifyScript(tx_signature[i], public_key.to_hex(), tx_decoded.get('vin'), i, flags=SCRIPT_VERIFY_P2SH)
        except KeyboardInterrupt:
            exit()
        except:
            input("\n\n\nWARNING: Unable to verify the Bitcoin Script. \n\nPress any key to send transaction....")


    #
    # TASK: if the transaction is valid, send it to the blockchain
    #
    print("\n\n\nBroadcasting Transaction...\n\n\n")
    rpc_connection.sendrawtransaction(tx.serialize())



def clearscreen():
    if name == 'nt':
        system('cls')
    else:
        system('clear')


def rpc_connect():
    displaybanner()
    # Establish RPC connection to local bitcoin node on port 18332
    # Request login credentials from user
    user = input("Connecting to localhost on port 18332\n\nUsername: ")
    pw = getpass(prompt="Password: ", stream=None)
    return AuthServiceProxy("http://%s:%s@localhost:18332" % (user, pw), timeout=3600)


def displaybanner():
    clearscreen()
    print("*" * 82)
    print("*{:80}*".format(" "))
    print("*                         BLOCK-521 Assignment - Script 2                        *")
    print("*{:80}*".format(" "))
    print("*                Bitcoin Testnet unlock and spend from P2SH address              *")
    print("*{:80}*".format(" "))
    print("*" * 82, "\n\n\n")


def displaybalance(balance, txlist):
    # Display UTXOs and balance
    headers = ["Index", "TxID", "Funds"]
    print(tabulate(txlist, headers, showindex='always', tablefmt="rst"))
    print("{:75}{}".format("Balance", balance))


if __name__ == "__main__":
    exit(main())

