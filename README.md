BLOCK-521 Digital Currency Programming Assigment

This assignment consists of a requirements file listing all the dependant packages needed to run the scripts, and 2 python scripts.

The first script p2sh_address_generator.py, generates a Pay 2 Script Hash Bitcoin Testnet address given a public key and locktime.
The second script spend_p2sh_funds.py, spends the funds sent to the P2SH address generated in script 1. 



Install instruction:

1) Extract the contents of james_comiskey.tgz to a local directory on a bitcoin testnet node
2) cd in to the folder containing the extracted contents of james_comiskey.tgz
2) Install dependant packages by entering the command:
sudo pip install -r requirements.txt
3) Make the 2 scripts executable by entering the command:
sudo chmod 755 *.py
4) Each script can be executed separately by typing:
python p2sh_address_generator.py
python spend_p2sh_funds.py

