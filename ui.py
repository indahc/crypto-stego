import tkinter as tk
from tkinter import *
from tkinter import Tk, Button, Label, Menu, Entry, INSERT, Frame, messagebox
import tkinter, Tkconstants, tkFileDialog
from tkFileDialog import askopenfilename
from PIL import Image, ImageTk
import PIL.Image, PIL.ImageTk
import cv2
import time
import sys
import os
import io
import argparse
import logging
import subprocess
import hashlib
import codecs
from humanfriendly import format_timespan
from time import time
from subprocess import Popen, PIPE
from filehash import FileHash
from twofish import Twofish
import hc128
import EDB

LARGE_FONT= ("Monserrat", 14) 
SMALL_FONT= ("Monserrat", 8) 


class CryptoProgram(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs) 
        self.title("Cipher-Code Program")
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand = True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        self.frames = {}
        for F in (MainMenu, HelpPage, EncryptTwofish, EncryptHC128, HideText, Verification, Extract, DecryptHC128, DecryptTwofish):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(MainMenu)
    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()

class MainMenu(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent, bg="#f6f6f6")
        mainMenuTitleText = tk.Label(self, text="Cryptography & Steganography", font=LARGE_FONT, bg="#f6f6f6", fg="#333333")
        mainMenuTitleText.pack(pady=30,padx=10)
        aboutText = tk.Label(self, text="This program can secure information and data by using cryptographic and steganographic implementations.\n"
                                        "First the message file will be encrypted by the Twofish Method,\n"
                                        "then it will be encrypted by the HC-128 Method and will be hidden into the image file.", font=SMALL_FONT, bg="#f6f6f6", fg="#333333")
        aboutText.pack(padx=30, pady=20)
        encryptButton = tk.Button(self, text="Encrypt Menu", bg="#6c8a9b", fg="#ffffff", width=20, relief=tk.FLAT,
                            command=lambda: controller.show_frame(EncryptTwofish))
        encryptButton.pack(pady=20)
        encryptText = tk.Label(self, text="***Encrypt the message into ciphertext and insert it into the image***", font=SMALL_FONT, bg="#f6f6f6", fg="#333333")
        encryptText.pack(padx=30)
        decryptButton = tk.Button(self, text="Decrypt Menu", bg="#6c8a9b", fg="#ffffff", width=20, relief=tk.FLAT,
                            command=lambda: controller.show_frame(Verification))
        decryptButton.pack(pady=20)
        decryptText = tk.Label(self, text="***Extract image-stego, and decrypt the ciphertext into message***", font=SMALL_FONT, bg="#f6f6f6", fg="#333333")
        decryptText.pack(padx=30)
        helpButton = tk.Button(self, text="Help Menu", width=16, bg="#f6f6f6", fg="#333333", relief=tk.FLAT,
                            command=lambda: controller.show_frame(HelpPage))
        helpButton.pack(side='right', pady=10, padx=20)

class HelpPage (tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#f6f6f6")
        # title
        aboutTitleLabel = tk.Label(self, text="Information & Data Security", bg="#f6f6f6", fg="#333333", font=LARGE_FONT)
        aboutTitleLabel.pack(pady=30,padx=30)
        # helpTitleLabel = tk.Label(self, text="Program Guide", bg="#f6f6f6", fg="#333333", font=LARGE_FONT)
        # helpTitleLabel.pack(pady=10,padx=30)
        encryptMenuLabel = tk.Label(self, text="Encrypt Menu:", bg="#f6f6f6", fg="#333333")
        encryptMenuLabel.pack(pady=5,padx=14)
        descriptionText = tk.Label(self, text="1. Select the txt file as the original message input, then enter the password that will be the key to the twofish encryption process.\n"
                                                "2. Next load the twofish ciphertext file which will be the HC-128 message input along with the password.\n"
                                                "3. and finally load the encrypted ciphertext file hc128 which will be inserted into the image file, and add a password to add security to the stego file.\n"
                                                "Stego file will be hashed to be used for file verification.", font=SMALL_FONT, bg="#f6f6f6", fg="#333333")
        descriptionText.pack(padx=14)
        decryptMenuLabel = tk.Label(self, text="Decrypt Menu:", bg="#f6f6f6", fg="#333333")
        decryptMenuLabel.pack(pady=5,padx=14)
        descriptionText = tk.Label(self, text="1. Select the stego image file and the hash image file from sender, then verify to make sure that the file is received is the original file.\n"
                                                "2. Then select the verified image stego and password for the image extraction process, the extraction process generates hidden-message.txt file.\n"
                                                "3. Browse for the hidden-message.txt file and the password as input decryption process HC-128\n"
                                                "4. Load the HC-128 plaintext as twofish ciphertext and password password for decrypting messages using twofish algorithm.\n" , font=SMALL_FONT, bg="#f6f6f6", fg="#333333")
        descriptionText.pack(padx=14)
        backButton = tk.Button(self, text="Main Menu", bg="#f6f6f6", fg="#333333", relief=tk.FLAT,
                            command=lambda: controller.show_frame(MainMenu))
        backButton.pack(side='bottom',pady=10, padx=10)

class EncryptTwofish (tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#f6f6f6")
        # title
        twofishEncryptTitleLabel = tk.Label(self, text="Encryption Twofish", bg="#f6f6f6", fg="#333333", font=LARGE_FONT)
        twofishEncryptTitleLabel.pack(pady=50)
        # frame text
        frameEntryText = Frame(self, bg="#f6f6f6")
        frameEntryText.pack(fill='x')
        # label
        twofishEncryptTextLabel = tk.Label(frameEntryText, text="Text can be Encrypt", bg="#f6f6f6", fg="#333333", width=20)
        twofishEncryptTextLabel.pack(side='left', padx=10, pady=5)
        # entry message
        global twofishEncryptPathFileText
        twofishEncryptPathFileText = tk.Entry(frameEntryText, width=70, bg="#ffffff", fg="#333333", relief=tk.FLAT)
        twofishEncryptPathFileText.pack(side='left', padx=14)
        # browse
        def openFile(): 
            global filename_twofish_text
            global normal_message
            global dir_path
            filename_twofish_text = tkFileDialog.askopenfilename(filetypes=[("Text File", ".txt")])
            if filename_twofish_text:
                with open(filename_twofish_text) as f:  
                    normal_message = open(filename_twofish_text,'r')
                    dir_path = os.path.split(filename_twofish_text)[0]
                    print("directory path : " + dir_path)
                    subprocess.Popen(['mkdir', dir_path+'/result']) # Call subprocess
                    normal_message = f.readline()
                    messageLength = len(normal_message)
                    print("normal message (length:"+str(messageLength)+") : "+normal_message)
                    twofishEncryptPathFileText.insert(tk.END, "%s" % (filename_twofish_text))
        openFileButton = tk.Button(frameEntryText, text="Browse", command=openFile, bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT)
        openFileButton.pack(fill='x', pady=5,padx=14)
        # frame password
        frameEntryPassword = Frame(self, bg="#f6f6f6")
        frameEntryPassword.pack(fill='x')
        # label
        twofishEncryptPasswordLabel = tk.Label(frameEntryPassword, text="Password", bg="#f6f6f6", fg="#333333", width=20)
        twofishEncryptPasswordLabel.pack(side='left', pady=5,padx=10)
        # entry password
        twofish_password = tk.StringVar()
        twofishEncryptPasswordText = tk.Entry(frameEntryPassword, textvariable=twofish_password, bg="#ffffff", fg="#333333", relief=tk.FLAT)
        twofishEncryptPasswordText.pack(fill='x', padx=14)
        # frame note
        frameNotePassword = Frame(self, bg="#f6f6f6")
        frameNotePassword.pack(fill='x')
        # note
        labelNote = tk.Label(frameNotePassword, text="*Password entered must be 16 character", bg="#f6f6f6", fg="#333333")
        labelNote.pack(side='right', padx=14)
        # function encrypt
        def twofishEncrypt():
            start_time = time()
            key = twofish_password.get()
            T = Twofish(key)
            n = 16
            pos = 0
            x = []
            res = ""
            for c in normal_message:
                if(pos%n==0):
                    if(pos==0):
                        res+=c
                    else:
                        x.append(res)
                        res = "" 
                        res+=c
                else:
                    res+=c
                pos=pos+1
            print(x)
            carry = res
            i = 0
            msg_len = 16-len(carry)
            while i < msg_len:
                carry += "_"
                i = i + 1
            x.append(carry)
            twofish_array = []
            for split_message in x:
                print("split normal message : "+split_message)
                cipher_twofish = T.encrypt(split_message)
                print("split cipher result : "+cipher_twofish.encode("hex"))
                cipher_twofish = cipher_twofish.encode("hex")
                twofish_array.append(cipher_twofish)
            global twofish_encrypted_message
            twofish_encrypted_message = "".join(twofish_array)
            print("merged cipher result : "+twofish_encrypted_message)
            messagebox.showinfo("Success", "Encrypt Twofish Success")
            end_time = time()
            time_taken = end_time - start_time
            hours, rest = divmod(time_taken,3600)
            minutes, seconds = divmod(rest, 60)
            print("Time taken:",  format_timespan(end_time - start_time))
        # frame button
        frameButtonEncrypt = Frame(self, bg="#f6f6f6")
        frameButtonEncrypt.pack(fill='x')
        # button encrypt
        encryptTwofishExecuteButton = tk.Button(frameButtonEncrypt, text="Encrypt Twofish", bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT, command=twofishEncrypt)
        encryptTwofishExecuteButton.pack(side='right', pady=10,padx=14)
        # button next
        nextButton = Button(self, text="Next", bg="#ffffff", fg="#333333", relief=tk.FLAT,
                    command=lambda: controller.show_frame(EncryptHC128))
        nextButton.pack(side='right', padx=14, pady=5)
        # button get file
        def writeFile():
            global filename_twofish_cipher
            filename_twofish_cipher = open(dir_path+'/result/cipher-twofish.txt','a+')
            filename_twofish_cipher.write(twofish_encrypted_message)
            filename_twofish_cipher.close()
            messagebox.showinfo("Success", "Save File Success")
        buttonWrite = Button(self, text = 'Write To File', bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT, command = writeFile)
        buttonWrite.pack(side='right')

class EncryptHC128 (tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#f6f6f6")
        # title
        hcEncryptTitleLabel = tk.Label(self, text="Encryption HC-128", bg="#f6f6f6", fg="#333333", font=LARGE_FONT)
        hcEncryptTitleLabel.pack(pady=50,padx=30)
        # frame text
        frameEntryText = Frame(self, bg="#f6f6f6")
        frameEntryText.pack(fill='x')
        # label title
        hcEncryptTextLabel = tk.Label(frameEntryText, text="Twofish Cipher Result", bg="#f6f6f6", fg="#333333", width=20)
        hcEncryptTextLabel.pack(side='left', padx=10, pady=5)
        # entry message
        load_twofish_cipher = tk.Text(frameEntryText, height=1, width=70, bg="#ffffff", fg="#333333", relief=tk.FLAT)
        load_twofish_cipher.pack(side='left', pady=5, padx=14)
        def loadTwofishCipher(): 
            load_twofish_cipher.insert(tk.END, twofish_encrypted_message)
        loadFileButton = tk.Button(frameEntryText, text="Load", command=loadTwofishCipher, bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT)
        loadFileButton.pack(fill='x', padx=14)
        # frame password
        frameEntryPassword = Frame(self, bg="#f6f6f6")
        frameEntryPassword.pack(fill='x')
        # label
        hcEncryptPasswordLabel = tk.Label(frameEntryPassword, text="Password", bg="#f6f6f6", fg="#333333", width=20)
        hcEncryptPasswordLabel.pack(side='left', pady=5,padx=10)
        # entry password
        hc128_password = tk.StringVar()
        hcEncryptPasswordText = tk.Entry(frameEntryPassword, textvariable=hc128_password, bg="#ffffff", fg="#333333", relief=tk.FLAT)
        hcEncryptPasswordText.pack(fill='x', padx=14)
        # frame note
        frameNotePassword = Frame(self, bg="#f6f6f6")
        frameNotePassword.pack(fill='x')
        # note
        labelNote = tk.Label(frameNotePassword, text="*Password entered must be 16 character", bg="#f6f6f6", fg="#333333")
        labelNote.pack(side='right', padx=14)
        # function encrypt
        def hcEncrypt():
            start_time = time()
            text = twofish_encrypted_message
            key = (hc128_password.get()).encode("hex")
            IV = key
            global hc_join
            n = 8
            ii = 0
            x = []
            res = ""
            for c in text:
                if(ii%n==0):
                    if(ii==0):
                        res+=c
                    else:
                        x.append(res)
                        res = ""
                        res+=c
                else:
                    res+=c
                ii=ii+1
            x.append(res) 
            print(x)
            print("Key = " + key)
            print("IV = " + IV)
            hc128.init(key, IV)
            k = hc128.keygen()
            print("Keystream generated: " + k)
            k = k.decode("hex")
            hc_array = []
            for twofish_chiper_res in x:
                print(twofish_chiper_res)
                twofish_chiper_res = twofish_chiper_res.decode('hex')
                cipher_text = ""
                for i in range(0, 4):
                    cipher_text += chr(ord(twofish_chiper_res[i]) ^ ord(k[i]))
                cipher_text = cipher_text.encode("hex")
                hc_array.append(cipher_text)
                print("Encrypted cipher text: " + cipher_text)
            hc_join = "".join(hc_array)
            print("cipher hc-128: ", hc_join)
            messagebox.showinfo("Success", "Encrypt HC-128 Success")
            end_time = time()
            time_taken = end_time - start_time
            hours, rest = divmod(time_taken,3600)
            minutes, seconds = divmod(rest, 60)
            print("Time taken:",  format_timespan(end_time - start_time))
        # frame button encrypt
        frameButtonEncrypt = Frame(self, bg="#f6f6f6")
        frameButtonEncrypt.pack(fill='x')
        # button encrypt
        encryptHcExecuteButton = tk.Button(frameButtonEncrypt, text="Encrypt HC-128", bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT, command=hcEncrypt)
        encryptHcExecuteButton.pack(side='right', pady=10,padx=14)
        # button next
        nextButton = Button(self, text="Next", bg="#ffffff", fg="#333333", relief=tk.FLAT,
                    command=lambda: controller.show_frame(HideText))
        nextButton.pack(side='right', padx=14, pady=5)
        # button writefile
        def writeFile():
            global filename_hc_cipher
            filename_hc_cipher = open(dir_path+'/result/cipher-hc128.txt','a+')
            filename_hc_cipher.write(hc_join)
            filename_hc_cipher.close()
            messagebox.showinfo("Success", "Save File Success")
        buttonWrite = Button(self, text = 'Write To File', bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT, command = writeFile)
        buttonWrite.pack(side='right')

class HideText (tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#f6f6f6")
        # title
        f5EmbedTitleLabel = tk.Label(self, text="Hide Text to Image", bg="#f6f6f6", fg="#333333", font=LARGE_FONT)
        f5EmbedTitleLabel.pack(pady=50,padx=10)
        # frame text
        frameEntryText = Frame(self, bg="#f6f6f6")
        frameEntryText.pack(fill='x')
        # label
        f5EmbedTextLabel = tk.Label(frameEntryText, text="Text can be Hide", bg="#f6f6f6", fg="#333333", width=20)
        f5EmbedTextLabel.pack(side='left', padx=10, pady=5)
        # load entry
        load_hc_cipher = tk.Text(frameEntryText, height=1, width=70, bg="#ffffff", fg="#333333", relief=tk.FLAT)
        load_hc_cipher.pack(side='left', padx=14, pady=5)
        def getEmbedText(): 
            load_hc_cipher.insert(tk.END, hc_join)
        loadFileButton = tk.Button(frameEntryText, text="Load", command=getEmbedText, bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT)
        loadFileButton.pack(fill='x', pady=5,padx=14)
        # frame image
        frameEntryImage = Frame(self, bg="#f6f6f6")
        frameEntryImage.pack(fill='x')
        # label
        f5EmbedImageLabel = tk.Label(frameEntryImage, text="Image File", bg="#f6f6f6", fg="#333333", width=20)
        f5EmbedImageLabel.pack(side='left', pady=5,padx=10)
        # image
        f5_image_path = tk.Entry(frameEntryImage, width=70, bg="#ffffff", fg="#333333", relief=tk.FLAT)
        f5_image_path.pack(side='left', padx=14)
        def openImage():
            global image
            global image_path
            filename_image = tkFileDialog.askopenfilename()
            image = Image.open(filename_image)
            image_path = filename_image
            f5_image_path.insert(tk.END, filename_image)
        # button browse
        openImageButton = tk.Button(frameEntryImage, text="Browse", bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT, command=openImage)
        openImageButton.pack(fill='x', pady=5,padx=14)
        # frame password
        frameEntryPassword = Frame(self, bg="#f6f6f6")
        frameEntryPassword.pack(fill='x')
        # label
        f5EmbedPasswordLabel = tk.Label(frameEntryPassword, text="Password", bg="#f6f6f6", fg="#333333", width=20)
        f5EmbedPasswordLabel.pack(side='left', pady=5,padx=10)
        # entry password
        f5_password = tk.StringVar()
        f5EmbedPasswordText = tk.Entry(frameEntryPassword, width=70, textvariable=f5_password, bg="#ffffff", fg="#333333", relief=tk.FLAT)
        f5EmbedPasswordText.pack(fill='x', padx=14)
        # frame 4
        frame4 = Frame(self, bg="#f6f6f6")
        frame4.pack(fill='x')
        # note
        labelNote = tk.Label(frameEntryPassword, text="*Password entered must be 16 character", bg="#f6f6f6", fg="#333333")
        labelNote.pack(side='right', padx=14)
        # function encrypt
        def embedImage():
            start_time = time()
            txt = hc_join
            print(txt)
            print(image_path)
            password = f5_password.get()
            print(password)
            subprocess.Popen(['python3', './EDB.py', '-i', image_path, '-d', txt, '-p', password, '-o', dir_path+'/result/output-stego.jpg', '-l', '5']) # Call subprocess
            messagebox.showinfo("Success", "Hide Text to Image Success")
            end_time = time()
            time_taken = end_time - start_time
            hours, rest = divmod(time_taken,3600)
            minutes, seconds = divmod(rest, 60)
            print("Time taken:",  format_timespan(end_time - start_time))
        # frame button encrypt
        frameButtonEncrypt = Frame(self, bg="#f6f6f6")
        frameButtonEncrypt.pack(fill='x')
        # button embed
        embedF5ExecuteButton = tk.Button(frameButtonEncrypt, text="Hide Text", bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT, command=embedImage)
        embedF5ExecuteButton.pack(side='right', pady=10, padx=14)
        nextButton = Button(self, text="Next", bg="#ffffff", fg="#333333", relief=tk.FLAT,
                    command=lambda: controller.show_frame(MainMenu))
        nextButton.pack(side='right', padx=14, pady=30)
        def getHashImage(): 
            global fileHash
            md5hasher = FileHash('md5')
            md5hasher.hash_file(dir_path+'/result/output-stego.jpg')
            fileHash = md5hasher.hash_file(dir_path+'/result/output-stego.jpg')
            filehash_image = open(dir_path+'/result/hash-image-password.txt', 'a+')
            filehash_image.write(fileHash)
            filehash_image.close()
            print(fileHash)
            messagebox.showinfo("File Hash", fileHash)
        loadFileButton = tk.Button(self, text="Get Hash Image", command=getHashImage, bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT)
        loadFileButton.pack(side='right', padx=5)

class Verification (tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#f6f6f6")
        # title
        verifyTitleLabel = tk.Label(self, text="Verify Image File", bg="#f6f6f6", fg="#333333", font=LARGE_FONT)
        verifyTitleLabel.pack(pady=50,padx=10)
        # frame image
        frameEntryImage = Frame(self, bg="#f6f6f6")
        frameEntryImage.pack(fill='x')
        # label
        verifyTextLabel = tk.Label(frameEntryImage, text="Image File", bg="#f6f6f6", fg="#333333", width=20)
        verifyTextLabel.pack(side='left', pady=5,padx=10)
        # entry stego image
        load_image_path= tk.Entry(frameEntryImage, width=70, bg="#ffffff", fg="#333333", relief=tk.FLAT)
        load_image_path.pack(side='left', padx=14)
        def browseImage():
            global fileImage
            # global path_imgsteg
            global filename_image
            filename_image = tkFileDialog.askopenfilename()
            dir_path = os.path.split(filename_image)[0]
            global imageFileHash
            imageFileHash = FileHash('md5')
            imageFileHash.hash_file(filename_image)
            imageFileHash = imageFileHash.hash_file(filename_image)
            print(imageFileHash)

            print("directory path : " + dir_path)
            subprocess.Popen(['mkdir', dir_path+'/decrypt-result']) # Call subprocess
            load_image_path.insert(tk.END, filename_image)
        # button browse
        openFileButton = tk.Button(frameEntryImage, text="Browse", bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT, command=browseImage)
        openFileButton.pack(fill='x', pady=5,padx=14)
        # frame password
        frameEntryHash = Frame(self, bg="#f6f6f6")
        frameEntryHash.pack(fill='x')
        # label
        hashImageLabel = tk.Label(frameEntryHash, text="Authentic Hash", bg="#f6f6f6", fg="#333333", width=20)
        hashImageLabel.pack(side='left', pady=5,padx=10)
        # entry password
        hashImageInput = tk.StringVar()
        imageHashText = tk.Entry(frameEntryHash, width=70, textvariable=hashImageInput, bg="#ffffff", fg="#333333", relief=tk.FLAT)
        imageHashText.pack(fill='x', padx=14)
        def verifyHash():
            # print(zipfileHash)
            hashImage = hashImageInput.get()
            print(hashImage)
            if ((imageFileHash == hashImage)): 
                messagebox.showinfo("Verification", "Hash file is correct")
                print("Hash file is correct") 
            else: 
                messagebox.showinfo("Verification", "Incorrect hash file")
                print("Incorrect hash file") 
        # button next
        nextButton = Button(self, text="Next", bg="#ffffff", fg="#333333", relief=tk.FLAT,
                    command=lambda: controller.show_frame(Extract))
        nextButton.pack(side='right', padx=14, pady=5)
        # button verify
        printHashButton = tk.Button(self, text="Verify", command=verifyHash, bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT)
        printHashButton.pack(side='right', pady=5)

class Extract (tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#f6f6f6")
        # title
        f5ExtractTitleLabel = tk.Label(self, text="Extract Image", bg="#f6f6f6", fg="#333333", font=LARGE_FONT)
        f5ExtractTitleLabel.pack(pady=50,padx=10)
        # frame image
        frameEntryImage = Frame(self, bg="#f6f6f6")
        frameEntryImage.pack(fill='x')
        # label
        f5ExtractTextLabel = tk.Label(frameEntryImage, text="Image File", bg="#f6f6f6", fg="#333333", width=20)
        f5ExtractTextLabel.pack(side='left', pady=5,padx=10)
        # entry stego image
        f5_image_stego = tk.Entry(frameEntryImage, width=70, bg="#ffffff", fg="#333333", relief=tk.FLAT)
        f5_image_stego.pack(side='left', padx=14)
        def openImage():
            global image
            # global path_imgsteg
            global filename_stego_image
            filename_stego_image = tkFileDialog.askopenfilename(initialdir = "/media/root/Disk1/cipher-code/result/",title = "Select file",filetypes = (("jpg files","*.jpg"),("all files","*.*")))
            image = Image.open(filename_stego_image)
            f5_image_stego.insert(tk.END, filename_stego_image)
        # button browse
        openImageButton = tk.Button(frameEntryImage, text="Browse", bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT, command=openImage)
        openImageButton.pack(fill='x', pady=5,padx=14)
        # frame password
        frameEntryPassword = Frame(self, bg="#f6f6f6")
        frameEntryPassword.pack(fill='x')
        # label
        f5ExtractPasswordLabel = tk.Label(frameEntryPassword, text="Password", bg="#f6f6f6", fg="#333333", width=20)
        f5ExtractPasswordLabel.pack(side='left', pady=5,padx=10)
        # entry password
        f5_password = tk.StringVar()
        f5EmbedPasswordText = tk.Entry(frameEntryPassword, width=70, textvariable=f5_password, bg="#ffffff", fg="#333333", relief=tk.FLAT)
        f5EmbedPasswordText.pack(fill='x', padx=14)
        # frame note
        frameNotePassword = Frame(self, bg="#f6f6f6")
        frameNotePassword.pack(fill='x')
        # note
        labelNote = tk.Label(frameNotePassword, text="*Password entered must be 16 character", bg="#f6f6f6", fg="#333333")
        labelNote.pack(side='right', padx=14)
        # function extract
        def extractStegoImage():
            # print(txt)
            start_time = time()
            password = f5_password.get()
            print(filename_stego_image)
            dir_path = os.path.split(filename_stego_image)[0]
            subprocess.Popen(['python3', './EDB.py', '-i', filename_stego_image, '-t', 'd', '-o', dir_path+'/decrypt-result/hidden-message.txt', '-p', password,  '-l', '5']) # Call subprocess
            messagebox.showinfo("Success", "Extract Image Success\nFile saved as hidden-message.txt")
            end_time = time()
            time_taken = end_time - start_time
            hours, rest = divmod(time_taken,3600)
            minutes, seconds = divmod(rest, 60)
            print("Time taken:",  format_timespan(end_time - start_time))
        # button next
        nextButton = Button(self, text="Next", bg="#ffffff", fg="#333333", relief=tk.FLAT,
                    command=lambda: controller.show_frame(DecryptHC128))
        nextButton.pack(side='right', padx=14, pady=5)
        # button extract
        extractF5ExecuteButton = tk.Button(self, text="Extract", bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT, command=extractStegoImage)
        extractF5ExecuteButton.pack(side='right', pady=10)

class DecryptHC128 (tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        tk.Frame.__init__(self, parent, bg="#f6f6f6")
        # title
        hcDecryptTitleLabel = tk.Label(self, text="Decryption HC-128", bg="#f6f6f6", fg="#333333", font=LARGE_FONT)
        hcDecryptTitleLabel.pack(pady=50,padx=30)
        # frame text
        frameEntryText = Frame(self, bg="#f6f6f6")
        frameEntryText.pack(fill='x')
        # label
        hcDecryptTextLabel = tk.Label(frameEntryText, text="Text can be Decrypt", bg="#f6f6f6", fg="#333333", width=20)
        hcDecryptTextLabel.pack(side='left', padx=10, pady=5)
        # entry message
        load_hc_cipher = tk.Entry(frameEntryText, width=70, bg="#ffffff", fg="#333333", relief=tk.FLAT)
        load_hc_cipher.pack(side='left', padx=14)
        def getCipherHc128(): 
            global filename_hc_cipher
            global txt
            filename_hc_cipher = tkFileDialog.askopenfilename()
            print(len(filename_hc_cipher))
            if filename_hc_cipher:
                with open(filename_hc_cipher) as f:
                    txt = open(filename_hc_cipher,'r')
                    txt = f.readline()
                    print(txt)
                    print(len(txt))
                    load_hc_cipher.insert(tk.END, "%s" % (filename_hc_cipher))
        openFileButton = tk.Button(frameEntryText, text="Browse", command=getCipherHc128, bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT)
        openFileButton.pack(fill='x', pady=5,padx=14)
        # frame password
        frameEntryPassword = Frame(self, bg="#f6f6f6")
        frameEntryPassword.pack(fill='x')
        # label
        hcDecryptPasswordLabel = tk.Label(frameEntryPassword, text="Password", bg="#f6f6f6", fg="#333333", width=20)
        hcDecryptPasswordLabel.pack(side='left', pady=5,padx=10)
        # entry password
        hc128_password = tk.StringVar()
        hcDecryptPasswordText = tk.Entry(frameEntryPassword, textvariable=hc128_password, bg="#ffffff", fg="#333333", relief=tk.FLAT)
        hcDecryptPasswordText.pack(fill='x', padx=14)
        # frame note
        frameNotePassword = Frame(self, bg="#f6f6f6")
        frameNotePassword.pack(fill='x')
        # note
        labelNote = tk.Label(frameNotePassword, text="*Password entered must be 16 character", bg="#f6f6f6", fg="#333333")
        labelNote.pack(side='right', padx=14)
        # function decrypt
        def hcDecrypt():
            start_time = time()
            text = txt
            key = (hc128_password.get()).encode("hex")
            IV = key
            global hc_join
            n = 8
            ii = 0
            x = []
            res = ""
            for c in text:
                if(ii%n==0):
                    if(ii==0):
                        res+=c
                    else:
                        x.append(res)
                        res = ""
                        res+=c
                else:
                    res+=c
                ii=ii+1
            x.append(res)
            print(x)
            print("Key = " + key)
            print("IV = " + IV)
            hc128.init(key, IV)
            hc128.i = 0
            k = hc128.keygen()
            print("Keystream generated: " + k)
            k = k.decode("hex")
            hc_arr = []
            for hc_chiper_res in x:
                print(hc_chiper_res)
                hc_chiper_res = hc_chiper_res.decode("hex")
                plain_text = ""
                for i in range(0, 4):
                    plain_text += chr(ord(hc_chiper_res[i]) ^ ord(k[i]))
                plain_text = plain_text.encode("hex")
                hc_arr.append(plain_text)
                print("Decrypt plain text: " + plain_text)
            hc_join = "".join(hc_arr)
            print(hc_join)
            messagebox.showinfo("Success", "Decrypt HC-128 Success")
            end_time = time()
            time_taken = end_time - start_time
            hours, rest = divmod(time_taken,3600)
            minutes, seconds = divmod(rest, 60)
            print("Time taken:",  format_timespan(end_time - start_time))
        # frame button decrypt
        frameButtonDecrypt = Frame(self, bg="#f6f6f6")
        frameButtonDecrypt.pack(fill='x')
        # button encrypt
        decryptHcExecuteButton = tk.Button(frameButtonDecrypt, text="Decrypt HC-128", bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT, command=hcDecrypt)
        decryptHcExecuteButton.pack(side='right', pady=10,padx=14)
        # button next
        nextButton = Button(self, text="Next", bg="#ffffff", fg="#333333", relief=tk.FLAT,
                    command=lambda: controller.show_frame(DecryptTwofish))
        nextButton.pack(side='right', padx=14, pady=5)
        def writeFile():
            global filenamePlainHc128
            dir_path = os.path.split(filename_hc_cipher)[0]
            filenamePlainHc128 = open(dir_path+'/plaintext-hc.txt','a+')
            filenamePlainHc128.write(hc_join)
            filenamePlainHc128.close()
            messagebox.showinfo("Success", "Save File Success")
        buttonWrite = Button(self, text = 'Write To File', bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT, command = writeFile)
        buttonWrite.pack(side='right')

class DecryptTwofish (tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#f6f6f6")
        # title
        twofishDecryptTitleLabel = tk.Label(self, text="Decryption Twofish",  font=LARGE_FONT, bg="#f6f6f6", fg="#333333")
        twofishDecryptTitleLabel.pack(pady=50,padx=10)
        # frame text
        frameEntryText = Frame(self, bg="#f6f6f6")
        frameEntryText.pack(fill='x')
        # label
        twofishDecryptTextLabel = tk.Label(frameEntryText, text="Text can be Decrypt", width=20, bg="#f6f6f6", fg="#333333")
        twofishDecryptTextLabel.pack(side='left', pady=0,padx=10)

        loadCipherTwofish = tk.Text(frameEntryText, height=1, width=70, bg="#ffffff", fg="#333333", relief=tk.FLAT)
        loadCipherTwofish.pack(side='left', pady=5, padx=14)
        # browse
        def getcipher_twofish(): 
            loadCipherTwofish.insert(tk.END, hc_join)
        loadFileButton = tk.Button(frameEntryText, text="Load", command=getcipher_twofish, bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT)
        loadFileButton.pack(fill='x', pady=5,padx=14)
        # frame password
        frameEntryPassword = Frame(self, bg="#f6f6f6")
        frameEntryPassword.pack(fill='x')
        # label
        twofishDecryptPasswordLabel = tk.Label(frameEntryPassword, text="Password", width=20, bg="#f6f6f6", fg="#333333")
        twofishDecryptPasswordLabel.pack(side='left', pady=5,padx=10)
        # entry password
        twofish_password = tk.StringVar()
        twofishDecryptPasswordText = tk.Entry(frameEntryPassword, textvariable=twofish_password, bg="#ffffff", fg="#333333", relief=tk.FLAT)
        twofishDecryptPasswordText.pack(fill='x', pady=5,padx=14)
        # frame note
        frameNotePassword = Frame(self, bg="#f6f6f6")
        frameNotePassword.pack(fill='x')
        # note
        labelNote = tk.Label(frameNotePassword, text="*Password entered must be 16 character", bg="#f6f6f6", fg="#333333")
        labelNote.pack(side='right', padx=14)
        # function decrypt
        def twofishDecrypt():
            # twf_var.get() #ini get password 
            start_time = time()
            global decrypt_twofish_join
            text = hc_join
            key = twofish_password.get()
            T = Twofish(key)
            n = 32
            ii = 0
            x = []
            res = ""
            for c in text:
                if(ii%n==0):
                    if(ii==0):
                        res+=c
                    else:
                        x.append(res)
                        res = ""
                        res+=c
                else:
                    res+=c
                ii=ii+1
            x.append(res) 
            print(x)
            twofish_array = []
            for twofish_plain_res in x:
                print(twofish_plain_res)
                twofish_decrypt = T.decrypt(twofish_plain_res.decode("hex"))
                print(twofish_decrypt)
                twofish_array.append(twofish_decrypt)
            decrypt_twofish_join = "".join(twofish_array)
            print(decrypt_twofish_join)
            messagebox.showinfo("Success", "Decrypt Twofish Success")
            end_time = time()
            time_taken = end_time - start_time
            hours, rest = divmod(time_taken,3600)
            minutes, seconds = divmod(rest, 60)
            print("Time taken:",  format_timespan(end_time - start_time))
        # frame button decrypt
        frameButtonDecrypt = Frame(self, bg="#f6f6f6")
        frameButtonDecrypt.pack(fill='x')
        # button encrypt
        decryptTwofishExecuteButton = tk.Button(frameButtonDecrypt, text="Decrypt Twofish", command=twofishDecrypt, bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT)
        decryptTwofishExecuteButton.pack(side='right', pady=10,padx=14)
        # button next
        nextButton = Button(self, text="Next", bg="#f6f6f6", fg="#333333", relief=tk.FLAT,
                    command=lambda: controller.show_frame(MainMenu))
        nextButton.pack(side='right', padx=14, pady=5)
        def writeFile():
            dir_path = os.path.split(filename_hc_cipher)[0]
            filenameTwofishPlain = open(dir_path+'/plaintext-twofish.txt','a+')
            filenameTwofishPlain.write(decrypt_twofish_join)
            filenameTwofishPlain.close()
            messagebox.showinfo("Success", "Save File Success")
        buttonWrite = Button(self, text = 'Write To File', bg="#6c8a9b", fg="#ffffff", relief=tk.FLAT, command = writeFile)
        buttonWrite.pack(side='right')

app = CryptoProgram()
app.mainloop()