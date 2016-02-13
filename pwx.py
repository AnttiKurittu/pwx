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
# Logo from http://patorjk.com/software/taag/
#
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
# DISCLAIMER
# This software is provided as-is and is provided for educational purposes only
# It has not been audited by professional cryptography experts and should be
# considered unsafe until proven otherwise.
#
# Future versions will most probably break backwards compatibility with
# existing databases so DO NOT USE THIS FOR ANY PURPOSES REQUIRING A SECURE
# PASSWORD
#
# (C)opyright Antti Kurittu 2016
# email antti@kurittu.org

import os
import sys
import random
import string
import hashlib
import argparse
import time
from Crypto.Cipher import AES
from Crypto import Random as CRandom

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
        iv = CRandom.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return iv + cipher.encrypt( raw )

    def decrypt( self, enc ):
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))

# Ask for a password and return a 32 character hash for AES encryption.
# Characters are not masked because the program prints a plaintext password anyway.
def getpass():
    if arg.password:
        password = arg.password
    else:
        try:
            password = raw_input("Master password: ")
        except KeyboardInterrupt:
            exit()
    # Hash the password to 32 characters AES can use it for encryption.
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
parser.add_argument("-l", "--length", metavar='length', type=int, help="Password length (default: 32)", default=32)
parser.add_argument("-w", "--workfactor", metavar='length', type=int, help="Work factor (n * 1000 iterations of sha256, default n = 500)", default=500)
parser.add_argument("-v", "--verbose", help='Produce more output', action="store_true", default=False)
parser.add_argument("-i", "--init", help="Initialize the database.", action="store_true", default=False)
arg = parser.parse_args()

# If init is called, create a new "database"
if arg.init:
    try:
        print("Initializing password database. Press CTRL-C to abort.")

        if os.path.isfile(ownPath + arg.file):
            overwrite = raw_input("Password database exists. Enter \"yes\" to generate new database: ")
        else:
            overwrite = "yes"

        if overwrite == "yes":
            password = getpass()
            # Get a random number to "break" the database size; multiples of 1000 suggest succesful
            # decryption.
            random.seed(os.urandom(256))
            database_size = random.randint(3000000, 4000000)
            # Get cryptographically safe random bytes to fill "database" file
            random_pool = os.urandom(database_size)
            print("DB verification hash: %s" % hashlib.sha256(random_pool).hexdigest())
            # Encrypt random data with master password
            random_encrypted_contents = AESCipher(password).encrypt(random_pool)
            database_file = open(ownPath + arg.file, "w+")
            database_file.write(random_encrypted_contents)
            database_file.close()
            print("Wrote the database file at %s, %s bytes" % (arg.file, database_size))
            exit()
        else:
            exit()
    except KeyboardInterrupt:
        exit()

if os.path.isfile(ownPath + arg.file):
    database_file = open(ownPath + arg.file, "r").read()
else:
    print("No database file found. Generate a database with --init or specify one with -f.")
    exit()

password = getpass()
# Get and decrypt "database" file.
decrypted_pool = AESCipher(password).decrypt(database_file)
if arg.verbose:
    print(" => DB verification hash: %s" % hashlib.sha256(decrypted_pool).hexdigest())

if arg.account:
    account = arg.account
else:
    account = raw_input("Key / account: ")

# Work factor for n iterations of sha256. This hash is used to seed the
# pseudorandom generator.
i = s = 0
work_factor = arg.workfactor * 1000
character_pool = string.ascii_letters + string.digits + '!@#$%^-&*()'

timer_start = time.clock()

while i < work_factor:
    account = hashlib.sha256(account).hexdigest()
    i += 1

timer_end = time.clock()
timer_result = (timer_end - timer_start)
if arg.verbose:
    print "\r => Working time for %s iterations was %s seconds" % ((arg.workfactor * 1000), timer_result)

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

output = ""
reduced_output = ""
seedbytes = ""
chunks = []
locations = []

# Get a list of chunks and locations inside chunks.
i = 0
while i < (arg.length * 4096):
    i += 1
    chunk = random.randint(0,999)
    location = random.randint(0,(chunk_size - 1))
    chunks.append(chunk)
    locations.append(location)
    if arg.verbose:
        sys.stdout.write("\r => Collated chunk %s, byte location %s (character %s/%s)" %
            ( str(chunk).zfill(4), str(location).zfill(len(str(chunk_size))), ( i / 4096 ), arg.length ))
        sys.stdout.flush()

# Assign seed bytes from choosing pseudorandomly from random source.
i = 0
seedpool = []
for chunk in chunks:
    i += 1
    location = locations.pop()
    newbyte = decrypted_chunks[chunk][location]
    if arg.verbose:
        if i == 1:
            sys.stdout.write("\n")
        sys.stdout.write("\r => Selecting byte %s out of %s: 0x%s" % (i, (arg.length * 4096), newbyte.encode('hex')))
    seedbytes = seedbytes + newbyte
    if len(seedbytes) == 256:
        # Append 64 seed bytes to a pool entry.
        seedpool.append(seedbytes)
        seedbytes = ""

if arg.verbose:
    sys.stdout.write("\n => Seed pool has %s entries." % len(seedpool))
# Finally generate the printable password based on new seed.
if arg.verbose:
    sys.stdout.write("\n => Building password from %s\n" % character_pool)
while len(output) < arg.length:
    # Re-seed the random.choice() for each character with a fresh entry from seed pool
    i = 0
    seed = ""
    while i < 16:
        i += 1
        seed = seed + seedpool.pop()
    random.seed(seed)
    # Pick a random character with this seed
    random_character = random.choice(character_pool)
    if arg.verbose:
        print " => Cycling seed %s... %s bytes, picked character \"%s\"" % (seed.encode('hex')[0:32], len(seed), random_character )
    output = output + random_character

print("Password: %s" % output)
exit()
