import json
import copy
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from datetime import datetime



class Transaction:
    def __init__(self, amount, payer, payee):
        self.amount = amount
        self.payer = payer
        self.payee = payee

    def __str__(self):
        return str(self.payer) + str(self.payee) + str(self.amount)

    def __bytes__(self):
        return bytes(str(self), 'utf-8')


class Block:
    def __init__(self, previousHash, transaction, proof):
        self.previousHash = previousHash
        self.transaction = transaction
        self.ts = datetime.now().timestamp()
        self.proof = proof

    def __str__(self):
        return str(self.previousHash) + str(self.transaction) + str(self.ts)

    def __bytes__(self):
        return bytes(str(self), 'utf-8')

    def hash(self):
        hasher = Hash(SHA256())
        hasher.update(bytes(self))
        blockhash = hasher.finalize()
        return blockhash


class Chain:
    def __init__(self, chain=None):
        if chain is None:
            wallet1 = Wallet()
            wallet2 = Wallet("./wallets/privatekey")
            chain = [Block(bytes(0), Transaction(1000000, wallet1.publickey.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), wallet2.publickey.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)), 1)]
        self.chain = chain
    def json(self):
        chain = copy.deepcopy(self)
        for i in range(len(chain.chain)):
            chain.chain[i].previousHash = chain.chain[i].previousHash.hex()
            chain.chain[i].transaction.payer = chain.chain[i].transaction.payer.hex()
            chain.chain[i].transaction.payee = chain.chain[i].transaction.payee.hex()
            chain.chain[i] = chain.chain[i].transaction.__dict__

        return json.dumps(chain.__dict__)



    def lastblock(self):
        return self.chain[len(self.chain) - 1]

    def addBlock(self, transaction, senderpubkey, signature):
        hasher = Hash(SHA256())
        hasher.update(bytes(transaction))
        transactionHash = hasher.finalize()
        try:
            senderpubkey.verify(signature, transactionHash)
        except:
            print("verification failed")
            return False
        proof = self.mine(transactionHash)
        newBlock = Block(self.lastblock().hash(), transaction, proof)
        self.chain.append(newBlock)
        print(
            f"New block added:\n  Last Hash: {self.lastblock().hash().hex()}\n  Transaction:\n    From: {transaction.payer.hex()}\n    To: {transaction.payee.hex()}\n    Amount: {transaction.amount}\n  Proof: {newBlock.proof}\n  Hash: {newBlock.hash().hex()}\n  TimeStamp {newBlock.ts}"
        )

    def mine(self, transactionhash):
        print('⛏Mining...')
        lasthash = self.lastblock().hash()
        m = 0
        while True:
            print(m)
            sys.stdout.write("\033[F")
            hasher = Hash(SHA256())
            hasher.update(transactionhash)
            hasher.update(bytes(m))
            hasher.update(lasthash)
            proof = hasher.finalize().hex()
            for i in range(0, 5):
                if proof[i] == 'f':
                    if i == 4:
                        print("🎉Mined Block🎉")
                        return m
                else:
                    break
            m += 1


class Wallet:
    def __init__(self, pem=None):
        if pem == None:
            key = ed25519.Ed25519PrivateKey.generate()
            self.privatekey = key
            self.publickey = key.public_key()
        else:
            f = open("./wallets/privatekey", "rb")
            privatebytes = f.read()
            print(privatebytes)
            key = ed25519.Ed25519PrivateKey.from_private_bytes(privatebytes)
            self.privatekey = key
            self.publickey = key.public_key()


    def sendmoney(self, amount, payee, chain):
        transaction = Transaction(amount, self.publickey, payee)
        hasher = Hash(SHA256())
        hasher.update(bytes(transaction))
        transactionHash = hasher.finalize()
        signature = self.privatekey.sign(transactionHash)
        chain.addBlock(transaction, self.publickey, signature)


def test():
    blockchain = Chain()

    wallet1 = Wallet()
    wallet2 = Wallet()
    wallet1.sendmoney(100, wallet2.publickey.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                      blockchain)
