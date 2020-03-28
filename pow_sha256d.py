import hashlib

def getPoWHash(header):
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()
