# pwx
Pwx generates deterministic passwords based on account name and pre-generated cryptographically random data..
Usage:

run "python pwx.py --init" to initialize password "database"

Enter master password and account name, password will be derived from account name so there's no need to save passwords. pwx will generate the same password for distinct key values.
Please note that pwx is NOT intended to be used in scenarios where password security is essential. It is merely a coding excercise. Use at your own risk.
Pwx will not keep record of "stored" passwords, since any key value will return a password. pwx will generate different passwords on 32/64 bit systems even with the same database because the Python pseudorandom generator uses a 32/64 bit version of the Mersenne Twister depending on platform. Don't expect to copy you password database from a mac to a raspberry pi and then have it produce the same passwords.

Please familiarize yourself with the source code if you intend to use this for something more than throwaway accounts.

Usage:
```bash
$ python pwx.py
Master password: example
Key / account: GitHub
Password: OaYnE-HR2xe9B6(xGuqkYy9vQFAanlQ^
```

```bash
$ python pwx.py
Master password: exmaplef
Key / account: GitHub
Password: @n@o0^QPmTY)4HlaBo8*X6$qfeYeRz19
```
