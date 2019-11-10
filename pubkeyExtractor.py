import sys

from umbral.keys import UmbralPrivateKey

def get_reseller_pubkeys(ethPk):
    try:
        reseller_privkey = UmbralPrivateKey.from_bytes(bytes.fromhex(ethPk))
    except IndexError:
        reseller_privkey = UmbralPrivateKey.gen_key()

    return reseller_privkey.get_pubkey();

print(get_reseller_pubkeys('4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d').to_bytes().hex())