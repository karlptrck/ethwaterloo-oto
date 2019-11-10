
import datetime
import sys
import json
import os
import shutil
import maya
from nucypher.characters.lawful import Bob, Ursula
from nucypher.config.characters import AliceConfiguration
from nucypher.utilities.logging import GlobalLoggerSettings
from umbral.keys import UmbralPublicKey, UmbralPrivateKey
######################
# Boring setup stuff #
######################
# Twisted Logger
from nucypher.utilities.sandbox.constants import TEMPORARY_DOMAIN
GlobalLoggerSettings.start_console_logging()
TEMP_ALICE_DIR = os.path.join("/", "tmp", "oto")
# if your ursulas are NOT running on your current host,
# run like this: python alicia.py 172.28.1.3:11500
# otherwise the default will be fine.
try:
   SEEDNODE_URI = sys.argv[1]
except IndexError:
   SEEDNODE_URI = "172.31.212.131:11500"
POLICY_FILENAME = "policy-metadata.json"
#######################################
# Alicia, the Authority of the Policy #
#######################################
# We get a persistent Alice.
# If we had an existing Alicia in disk, let’s get it from there
passphrase = "TEST_ALICIA_INSECURE_DEVELOPMENT_PASSWORD"
# If anything fails, let’s create Alicia from scratch
# Remove previous demo files and create new ones
shutil.rmtree(TEMP_ALICE_DIR, ignore_errors=True)
ursula = Ursula.from_seed_and_stake_info(seed_uri=SEEDNODE_URI,
                                        federated_only=True,
                                        minimum_stake=0)
alice_config = AliceConfiguration(
   config_root=os.path.join(TEMP_ALICE_DIR),
   domains={TEMPORARY_DOMAIN},
   known_nodes={ursula},
   start_learning_now=False,
   federated_only=True,
   learn_on_same_thread=True,
)
alice_config.initialize(password=passphrase)
alice_config.keyring.unlock(password=passphrase)
alicia = alice_config.produce()
# We will save Alicia’s config to a file for later use
alice_config_file = alice_config.to_configuration_file()
# Let’s get to learn about the NuCypher network
alicia.start_learning_loop(now=True)
enc_privkey = UmbralPrivateKey.gen_key()
sig_privkey = UmbralPrivateKey.gen_key()


print(enc_privkey.to_bytes().hex())
print(enc_privkey.get_pubkey().to_bytes().hex())
verifying_key = UmbralPublicKey.from_hex(enc_privkey.get_pubkey().to_bytes().hex()),
encrypting_key = UmbralPublicKey.from_hex(sig_privkey.get_pubkey().to_bytes().hex())

label = "QmVahkTzLmU88CayjyZrRvqX78BmjjqH4iW26tNPvYQ18M"
label = label.encode()

policy_pubkey = alicia.get_policy_encrypting_key_from_label(label)
print("The policy public key for "
      "label '{}' is {}".format(label.decode("utf-8"), policy_pubkey.to_bytes().hex()))

SUBSCRIBER_PUBLIC_JSON = 'subscriber.public.json'
SUBSCRIBER_PRIVATE_JSON = 'subscriber.private.json'

enc_privkey = UmbralPrivateKey.gen_key()
sig_privkey = UmbralPrivateKey.gen_key()

subscriber_privkeys = {
      'enc': enc_privkey.to_bytes().hex(),
      'sig': sig_privkey.to_bytes().hex(),
}

with open(SUBSCRIBER_PRIVATE_JSON, 'w') as f:
      json.dump(subscriber_privkeys, f)

enc_pubkey = enc_privkey.get_pubkey()
sig_pubkey = sig_privkey.get_pubkey()
subscriber_pubkeys = {
      'enc': enc_pubkey.to_bytes().hex(),
      'sig': sig_pubkey.to_bytes().hex()
}

with open(SUBSCRIBER_PUBLIC_JSON, 'w') as f:
      json.dump(subscriber_pubkeys, f)

# print('enc== ' + doctor_pubkeys['enc'])
# print('sig== ' + doctor_pubkeys['sig'])

subscriber = Bob.from_public_keys(verifying_key=subscriber_pubkeys['sig'],
                                      encrypting_key=subscriber_pubkeys['enc'],
                                      federated_only=True)

policy_end_datetime = maya.now() + datetime.timedelta(days=5)
# - m-out-of-n: This means Alicia splits the re-encryption key in 5 pieces and
#               she requires Bob to seek collaboration of at least 3 Ursulas
m, n = 2, 3


print("Creating access policy for the subscriber...")
policy = alicia.grant(bob=subscriber,
                      label=label,
                      m=m,
                      n=n,
                      expiration=policy_end_datetime)
print("Done!")


policy_info = {
    "policy_pubkey": policy.public_key.to_bytes().hex(),
    "alice_sig_pubkey": bytes(alicia.stamp).hex(),
    "label": label.decode("utf-8"),
}

filename = POLICY_FILENAME
with open(filename, 'w') as f:
    json.dump(policy_info, f)