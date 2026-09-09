"""The two Python patterns Bandit measurably misses. Everything else is Bandit's."""
from Crypto.Cipher import AES


def ecb_via_pycryptodome(key):
    return AES.new(key, AES.MODE_ECB)


def generic_debug_server(app):
    app.run(debug=True)
