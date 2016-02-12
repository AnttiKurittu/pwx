#
#        _____    _____
#    ___|\    \  |\    \   _____ _____      _____
#   |    |\    \ | |    | /    /|\    \    /    /
#   |    | |    |\/     / |    || \    \  /    /
#   |    |/____/|/     /_  \   \/  \____\/____/
#   |    ||    ||     // \  \   \  /    /\    \
#   |    ||____||    |/   \ |    |/    /  \    \
#   |____|      |\ ___/\   \|   //____/ /\ \____\
#   |    |      | |   | \______/ |    |/  \|    |
#   |____|       \|___|/\ |    | |____|    |____|
#     \(            \(   \|____|/  \(        )/
#      '             '      )/      '        '
#                           '
# pwx generates deterministic passwords based on pre-generated cryptographically
# random database.
#
# pwx first generates a cryptographically secure random pool of data, which it
# then encrypts with a user-supplied master password. The pool is generated using
# operating system entropy source with os.urandom.
#
# Individual account passwords are derived from this random data using a
# pseudorandom function that produces a determined result with a given account
# name and password length.
#
# The benefit from this is that the attacker can only guess when the decryption
# has succeeded since wrong master passwords provide right-looking answers
# but based on junk data. Correct AES key produces the right passwords.
#
# The password "database" has no information on what keys are stored there.
# Any key can be stored in this pool so it can't by definition leak information
# about which passwords it holds. It is impossible to list the "stored" passwords
# so the user needs to remember the exact account name for a given password.
#
# This software is provided as-is and is provided for educational purposes only
# It has not been audited by professional cryptography experts and should be
# considered unsafe until proven otherwise.
#
# (C)opyright Antti Kurittu 2016
# email antti@kurittu.org

import os
import sys
import random
import string
import hashlib
import argparse
from Crypto.Cipher import AES
from Crypto import Random

# Define AESCipher class
# Source: http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class AESCipher:
    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return iv + cipher.encrypt( raw )

    def decrypt( self, enc ):
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))
        return cipher.decrypt( enc[16:] )

# Ask for a password and return a 32 character hash for AES encryption.
# Characters are not masked because the program prints a plaintext password anyway.
def getpass():
    if arg.password:
        password = arg.password
    else:
        password = raw_input("Master password: ")
    passwordhash = hashlib.md5(hashlib.sha256(password).hexdigest()).hexdigest()
    return passwordhash

ownPath = os.path.dirname(sys.argv[0]) + "/"
if ownPath is "/" or ownPath is "":
    ownPath = "./"

# Get command line arguments.
parser = argparse.ArgumentParser(description='Get actions')
parser.add_argument("-a", "--account", metavar="account name", help="Account to view the password for.", type=str)
parser.add_argument("-p", "--password", metavar='password', type=str, help="Master password (WARNING! log files may store your shell commands.")
parser.add_argument("-f", "--file", metavar='database file', type=str, help="database file to use (default: ./pwdb.bin)", default="pwdb.bin")
parser.add_argument("-l", "--length", metavar='length', type=int, help="Password length (default: 24)", default=24)
parser.add_argument("-v", "--verbose", help='Produce more output', action="store_true", default=False)
parser.add_argument("-i", "--init", help="Initialize the database.", action="store_true", default=False)
arg = parser.parse_args()

# If init is called, create a new "database"
if arg.init == True:
    print("Initializing password database. Press CTRL-C to abort.")

    if os.path.isfile(ownPath + arg.file) == True:
        overwrite = raw_input("Password database exists. Enter \"yes\" to generate new database: ")
    else:
        overwrite = "yes"

    if overwrite == "yes":
        password = getpass()
        init_database_size = int(input("Specify new database size in KB (suggested size 5000): "))
        length = (1000 * init_database_size)
        # Get cryptographically safe random bytes to fill "database" file
        random_pool = os.urandom(length)
        # Encrypt random data with master password
        print("Verification hash: %s" % hashlib.sha256(random_pool).hexdigest())
        random_encrypted_contents = AESCipher(password).encrypt(random_pool)
        database_file = open(ownPath + arg.file, "w+")
        database_file.write(random_encrypted_contents)
        database_file.close()
        print("Wrote the database file at %s" % arg.file)
        exit()
    else:
        exit()

if os.path.isfile(ownPath + arg.file) == True:
    database_file = open(ownPath + arg.file, "r").read()
else:
    print("No database file found. Generate a database with --init or specify one with -f.")
    exit()

password = getpass()
# Get and decrypt "database" file.
decrypted_pool = AESCipher(password).decrypt(database_file)
print("Verification hash: %s" % hashlib.sha256(decrypted_pool).hexdigest())

if arg.account:
    account = arg.account
else:
    account = raw_input("Key / account: ")

i = s = 0
# Work factor for n iterations of sha256. This hash is used to seed the
# pseudorandom generator.
while i < 1000000:
    account = hashlib.sha256(account).hexdigest()
    i += 1
    s += 1
    if s == 1:
        sys.stdout.write("\rPassword: .")
        sys.stdout.flush()
    if s == 50000:
        sys.stdout.write("\rPassword: :")
        sys.stdout.flush()
    if s == 100000:
        sys.stdout.write("\rPassword: +")
        sys.stdout.flush()
    if s == 150000:
        s = 0
        sys.stdout.write("\rPassword: -")
        sys.stdout.flush()

sys.stdout.write("\r\r\r\r\r\r\r\r\r\r")
pseudorandom_seed = hashlib.sha256(str(len(account)) + account + str(arg.length)).hexdigest()

# Split database into a thousand individual chunks.
chunk_size = len(decrypted_pool) / 1000
decrypted_chunks = []
i = 0
while i < int( len(decrypted_pool) / chunk_size ):
    cursor = i * chunk_size
    decrypted_chunks.append(decrypted_pool[cursor:cursor + chunk_size])
    i += 1

# Iterate a little more after adding account length and password length into the mix.
i = 0
while i < 1000:
    pseudorandom_seed = hashlib.sha256(pseudorandom_seed).hexdigest()
    i += 1

# Seed the pseudorangom generator for determining chunk and a byte location inside it.
random.seed(pseudorandom_seed)

output = seedbytes = ""
chunks = []
locations = []
character_pool = string.ascii_letters + string.digits + '!@#$%^-&*()'

# Get a list of chunks and locations inside chunks.
i = 0
while i < (arg.length * 4096):
    chunk = random.randint(0,999)
    location = random.randint(0,(chunk_size - 1))
    chunks.append(chunk)
    locations.append(location)
    if arg.verbose == True:
        sys.stdout.write("\r => Collated chunk %s, byte location %s " % ( str(chunk).zfill(4), str(location).zfill(len(str(chunk_size))) ))
        sys.stdout.flush()
    i += 1

# Assign seed bytes from choosing pseudorandomly from random source.
i = 0
for chunk in chunks:
    i += 1
    location = locations.pop()
    newbyte = decrypted_chunks[chunk][location]
    if arg.verbose:
        if i == 1:
            sys.stdout.write("\n")
        sys.stdout.write("\r => Selecting byte %s out of %s: 0x%s" % (i, (arg.length * 4096), newbyte.encode('hex')))
    seedbytes = seedbytes + newbyte

# Re-initialize the random seed

if arg.verbose == True:
    sys.stdout.write("\n => Selected %s seed bytes with sha256 value of %s\n" % (len(seedbytes), hashlib.sha256(seedbytes).hexdigest()))

random.seed(seedbytes)

# Finally generate the printable password based on new seed.
if arg.verbose == True:
    sys.stdout.write(" => Building password from %s\n" % character_pool)
while len(output) < arg.length:
    output = output + random.choice(character_pool)

print("Password: %s" % output)
decrypted_pool = seedbytes = None
exit()
