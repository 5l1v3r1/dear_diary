#!/usr/bin/python
import os, sys, getpass, time, hashlib
from Crypto import Random
from Crypto.Cipher import AES
from Tkinter import *

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

# Standaard sleutel om bestanden te versleutelen. Doet standaard niks.
key = b'\x01\xeb\xff\xe2\xca#\xacT\xf3\xfeKh\xc1{\x8b\x86\xa5\x96\\0\xbf\x93E\xa1\xce\xc9\x9e\xb8e\x11\xa1\x8a'

class MainWindow(Tk):
    def __init__(self):
        Tk.__init__(self)
        self.title(string = " Dear Diary ")
        self.resizable(0,0)

        self.options = {
            'title' : StringVar(),
            'password' : StringVar(),
            'decryptpassword' : StringVar(),

        }

        menu = Menu(self)
        menu.add_command(label="Quit!", command=self.quit)
        menu.add_command(label="Save File", command=self.save)

        self.config(menu=menu)

        settings = LabelFrame(self, text = 'Settings', width = 450, height = 110)
        settings.grid(row = 0, column = 1)

        Label(settings, text = 'Title').grid(row = 0, column = 1)
        self.options['title'] = Entry(settings, textvariable = self.options['title'])
        self.options['title'].grid(row = 0, column = 2)

        Label(settings, text = 'Set Password').grid(row = 1, column = 1)
        self.options['password'] = Entry(settings, textvariable = self.options['password'], show = '*')
        self.options['password'].grid(row = 1, column = 2)
        self.options['error'] = Label(self, text = '').grid(row = 3, column = 1)


        textfield = LabelFrame(self, text = 'Textfield', relief = GROOVE)
        textfield.grid(row = 2, column = 1, columnspan = 2)

        self.options['textfield1'] = Text(textfield, foreground="black", background="white", highlightcolor="white", highlightbackground="black", height = 35, width = 100)
        self.options['textfield1'].grid(row = 0, column = 1)

        select = LabelFrame(self, text = 'Select diary', relief = GROOVE, labelanchor = 'nw', width = 100, height = 50)
        select.grid(row = 0, column = 2)
        self.options['list1'] = Listbox(select, width = 50, height = 10)
        self.options['list1'].grid(row = 0, column = 1)
        self.options['list1'].bind("<Double-Button-1>", self.open_file)

        tel_boeken = 0
        for path, subdirs, files in os.walk('.'):
            for name in files:
                if name.endswith('.diary.zez'):
                    tel_boeken += 1
                    self.options['list1'].insert(END, path + '/' + name)

        self.title(string = 'Dear Diary | Aantal bestanden: %i' % tel_boeken)

    def save(self):
        # Check if password
        if not self.options['password'].get():
            self.options['error'] = Label(self, text = 'Please, enter a password').grid(row = 3, column = 1)

        # Check if title
        if not self.options['title'].get():
            self.options['error'] = Label(self, text = 'Please, enter a title').grid(row = 3, column = 1)

        key = hashlib.sha256(self.options['password'].get()).digest()

        # Write file
        with open('./%s_%s.diary' % (time.strftime('%d-%m-%Y'), self.options['title'].get()), 'w+') as f:
            f.write(self.options['textfield1'].get('1.0', END))
            f.close()

        # Encrypt file
        enc = './%s_%s.diary' % (time.strftime('%d-%m-%Y'), self.options['title'].get())
        encrypt_file(enc, key)
        os.remove(enc)

        # Clear input fields
        self.options['list1'].delete(0, END)
        self.options['title'].delete(0, END)
        self.options['password'].delete(0, END)
        self.options['textfield1'].delete('1.0', END)
        self.options['title'].focus()

        tel_boeken = 0
        for path, subdirs, files in os.walk('.'):
            for name in files:
                if name.endswith('.diary.zez'):
                    tel_boeken += 1
                    self.options['list1'].insert(END, path + '/' + name)

        self.title(string = 'Dear Diary | Aantal bestanden: %i' % tel_boeken)


    def open_file(self, event):
        self.enter_pwd = Toplevel()
        self.enter_pwd.title(string = 'Enter password')
        self.enter_pwd.resizable(0,0)

        Label(self.enter_pwd, text = 'Password').grid(row = 0, column = 1)
        self.options['decryptpassword'] = Entry(self.enter_pwd, textvariable = self.options['decryptpassword'], show = '*')
        self.options['decryptpassword'].grid(row = 0, column = 2)
        self.options['decryptpassword'].bind('<Return>', self.decrypt_now)
        self.options['decryptpassword'].focus()

    def decrypt_now(self, event):
        key = hashlib.sha256(self.options['decryptpassword'].get()).digest() # Set key
        selection=self.options['list1'].get(self.options['list1'].curselection()) # Grab file

        decrypt_file(selection, key) # Decryt file
        dec_file = selection.split('.zez')[0]
        dagboek = open(dec_file).read() # Open decrypted file
        self.options['textfield1'].delete('1.0', END) # Clear textfield
        self.options['textfield1'].insert('1.0', dagboek) # Show content in textfield1
        os.remove(dec_file) # Remove decrypted file

        self.enter_pwd.destroy()


if __name__ in '__main__':
    try:
        dagboek = MainWindow()
        dagboek.mainloop()
    except Exception as e:
        print(e)
