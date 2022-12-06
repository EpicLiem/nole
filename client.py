from requests import post
from blockchain import *
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives import serialization

wallet1 = Wallet()
wallet2 = Wallet("./wallets/privatekey")



amount = int(input("amount: "))
transaction = Transaction(amount, wallet1.publickey.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), wallet2.publickey.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
hasher = Hash(SHA256())
hasher.update(bytes(transaction))
transactionHash = hasher.finalize()
signature = wallet1.privatekey.sign(transactionHash).hex()
wallet1b = wallet1.publickey.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
wallet2b = wallet2.publickey.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
payload = {"transaction":{"from": wallet1b, "to": wallet2b, "amount": amount}, "signature": str(signature)}
post("http://127.0.0.1:5000/transaction", json=payload)