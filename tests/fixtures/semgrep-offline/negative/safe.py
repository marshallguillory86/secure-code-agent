"""Safe twins of the two Python patterns this profile still owns."""
from Crypto.Cipher import AES


def authenticated_mode(key, nonce):
    return AES.new(key, AES.MODE_GCM, nonce=nonce)


def production_server(app):
    app.run(debug=False)
