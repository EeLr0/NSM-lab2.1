def createMessage(from_user, to_user, ciphertext, nonce, signature):
    return {
        "type": "message",
        "from": from_user,
        "to": to_user,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "signature": signature.hex(),
    }
