import json
from flask import Flask, request
from blockchain import *
from cryptography.hazmat.primitives.asymmetric import ed25519


app = Flask(__name__)

chain = Chain()

@app.route("/transaction", methods=['POST'])
def newtransaction():
    req = request.json
    trans = req["transaction"]
    payer = bytes.fromhex(trans["from"])
    payee = bytes.fromhex(trans["to"])
    signature = bytes.fromhex(req["signature"])
    transaction = Transaction(trans["amount"], payer, payee)
    chain.addBlock(transaction, ed25519.Ed25519PublicKey.from_public_bytes(payer), signature)
    return "data recieved"

@app.route("/chain", methods=['GET'])
def getchain():
    return chain.json()
