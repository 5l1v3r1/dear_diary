#!/usr/bin/python

import os, sys, getpass, time, hashlib
from Crypto import Random
from Crypto.Cipher import AES

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def encrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    with open(file_name + ".zez", 'wb') as fo:
        fo.write(enc)

def decrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    with open(file_name[:-4], 'wb') as fo:
        fo.write(dec)

def schrijven():
    regels = []
    titel = raw_input('Titel: ')
    try:
        while True:
            plaintxt = raw_input('>> ')
            regels.append(plaintxt)

    except KeyboardInterrupt:
        # Write and Quit
        print('\n')
        passwd = getpass.getpass("Password: ")
        key = hashlib.sha256(passwd).digest()

        # Debug
        #print("Wachtwoord: ", key)

        # Tel het aantal regels
        print('\nRegels: %i' % len(regels))

        # Schrijf de Regels
        with open('./%s_%s.diary' % (time.strftime('%d-%m-%Y'),titel), 'w+') as f:
            for l in regels:
                f.write(l + '\n')
            f.close()

        # Encrypt the file
        enc = './%s_%s.diary' % (time.strftime('%d-%m-%Y'), titel)
        print('Saved:' + enc)
        encrypt_file(enc, key)
        os.remove(enc)

        # Print de regels
        #for l in regels:
        #    print(l)

def dagboek_lezen():
    tel_boeken = -1
    dagboeken = []

    for path, subdirs, files in os.walk('.'):
        for name in files:
            if name.endswith('.diary.zez'):
                tel_boeken += 1
                dagboeken.append(path + '/' + name)

    c = -1
    for items in dagboeken:
        c +=1
        print('\t\033[1;96m%i)\033[0m ' % int(c) + items)

    try:
        num = input('#?: ')

        # Opgeven wachtwoord
        passwd = getpass.getpass("Password: ")
        key = hashlib.sha256(passwd).digest()

        # Debug
        #print("Wachtwoord: ", key)

        # Ontsleutelen
        de_enc = dagboeken[int(num)]
        decrypt_file(de_enc, key)
        #os.remove(de_enc + ".zez")

        # Lezen
        dagboek = open(dagboeken[int(num)].split('.zez')[0]).read()
        print('\n')
        print(dagboek)

        # Verwijder het ontsleutelde dagboek
        os.remove(dagboeken[int(num)].split('.zez')[0])


    except Exception as e:
        print('[Error] %s\n' % e)
        num = input('#?: ')

# Standaard sleutel om bestanden te versleutelen
key = b'\x01\xeb\xff\xe2\xca#\xacT\xf3\xfeKh\xc1{\x8b\x86\xa5\x96\\0\xbf\x93E\xa1\xce\xc9\x9e\xb8e\x11\xa1\x8a'

opt = True

try:
    while opt:
        print("""
    Options:
        1) Encrypt a file
        2) Decrypt a file
        3) Encrypt all files in a directory
        4) Decrypt all files in a directory
        5) Schrijven en versleutelen
        6) Dagboek lezen
        99) Quit
        """)
        opt = raw_input("[#?] ")
        if opt == "1":
            enc = raw_input("Path to file (encrypt): ")
            encrypt_file(enc, key)
            os.remove(enc)
        elif opt == "2":
            de_enc = raw_input("Path to file (decrypt): ")
            decrypt_file(de_enc + ".zez", key)
            os.remove(de_enc + ".zez")
        elif opt == "3":
            counter = 0
            enc = raw_input("Path to directory (encrypt): ")
            for path, subdirs, files in os.walk(enc):
                for name in files:
                    if name.endswith(".zez"):
                        print("[ Skipped ] %s" % name)
                    elif "." in name:
                        encrypt_file(os.path.join(path, name), key)
                        print("[ Encrypting ] %s" % name)
                        counter = counter+1
                        os.remove(os.path.join(path, name))
            print("\n[ Done ] Encrypted %i files" % counter)
        elif opt == "4":
            counter = 0
            de_enc = raw_input("Path to directory (decrypt): ")
            for path, subdirs, files in os.walk(de_enc):
                for name in files:
                    # If it has an extention, it must be a file
                    if name.endswith(".zez"):
                        decrypt_file(os.path.join(path, name), key)
                        print("[ Decrypting ] %s" % name)
                        counter = counter+1
                        os.remove(os.path.join(path, name))
                    else:
                        print("[ Skipped ] %s" % name)
            print("\n[ Done ] Decrypted %i files" % counter)
        elif opt == "5":
            schrijven()
        elif opt == "6":
            dagboek_lezen()
        elif opt == "99":
            sys.exit()
        else:
            print("[!] Invalid selection!")

except KeyboardInterrupt:
    print("\n")
    sys.exit()
