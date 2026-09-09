"""The safe counterpart of every positive case. No rule may fire here.

Each function is deliberately close to its vulnerable twin: the point is to
catch a rule that matches the shape of the call rather than the unsafe thing
about it.
"""

import ast
import hashlib
import json
import os
import secrets
import subprocess
import tempfile
import zipfile

import lxml.etree
import requests
import yaml
from Crypto.Cipher import AES


def command_without_shell(cmd_args):
    subprocess.run(cmd_args, shell=False, check=True)
    subprocess.Popen(["/usr/bin/git", "status"])


def literal_evaluation(payload):
    return ast.literal_eval(payload)


def safe_deserialization(blob):
    json.loads(blob)
    return yaml.safe_load(blob)


def strong_crypto(data, key, nonce):
    hashlib.sha256(data)
    hashlib.blake2b(data)
    return AES.new(key, AES.MODE_GCM, nonce=nonce)


def unpredictable_values():
    return secrets.token_hex(32)


def tls_verified(url):
    return requests.get(url, timeout=10)


def single_member_extraction(path, dest, member):
    with zipfile.ZipFile(path) as archive:
        return archive.extract(member, dest)


def xml_without_entities(data):
    parser = lxml.etree.XMLParser(resolve_entities=False)
    return lxml.etree.fromstring(data, parser)


def secure_temp():
    return tempfile.NamedTemporaryFile(delete=False)


def owner_only_permissions(path):
    os.chmod(path, 0o600)


def parameterized_sql(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))


def production_server(app):
    app.run(debug=False)


def ordinary_assertions(total):
    assert total > 0, "total must be positive"


def bind_loopback(sock, app):
    sock.bind(("127.0.0.1", 8080))
    app.run(host="127.0.0.1")
