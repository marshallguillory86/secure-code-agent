"""Every Python rule in the offline profile must flag something here."""

import hashlib
import marshal
import os
import pickle
import random
import shelve
import subprocess
import tarfile
import tempfile
import xml.sax
import zipfile

import lxml.etree
import requests
import yaml
from Crypto.Cipher import AES, ARC4, DES


def command_injection(cmd):
    subprocess.run(cmd, shell=True)
    subprocess.Popen(cmd, shell=True)


def shell_helpers(cmd):
    os.system(cmd)
    os.popen(cmd)


def code_injection(payload):
    eval(payload)
    exec(payload)


def unsafe_deserialization(blob, path):
    pickle.loads(blob)
    marshal.loads(blob)
    shelve.open(path)
    return yaml.load(blob)


def broken_crypto(data, key):
    hashlib.md5(data)
    hashlib.sha1(data)
    DES.new(key, DES.MODE_ECB)
    ARC4.new(key)
    AES.new(key, AES.MODE_ECB)


def predictable_values():
    return random.randint(0, 1000)


def tls_disabled(url):
    return requests.get(url, verify=False)


def archive_extraction(path, dest):
    zipfile.ZipFile(path).extractall(dest)
    tarfile.open(path).extractall(dest)


def xml_entities(data):
    parser = lxml.etree.XMLParser(resolve_entities=True)
    xml.sax.make_parser()
    return parser


def insecure_temp():
    return tempfile.mktemp()


def loose_permissions(path):
    os.chmod(path, 0o777)
    os.umask(0)


def sql_building(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")


def debug_server(app):
    app.run(debug=True)


def assert_enforcement(user):
    assert user.is_admin, "not an admin"


def bind_everywhere(sock, app):
    sock.bind(("0.0.0.0", 8080))
    app.run(host="0.0.0.0")
