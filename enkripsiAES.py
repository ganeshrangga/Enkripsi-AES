from Crypto.Cipher import AES
from Crypto import Random
import base64
import os


def encryption(message):
    BLOCK_SIZE = 16
    key = Random.new().read(16)
    iv = Random.new().read(16)
    PADDING = '{'

    pad = lambda message: message + (BLOCK_SIZE - len(message) % BLOCK_SIZE) * PADDING

    EncodeAES = lambda c, message: base64.b64encode(c.encrypt(pad(message).encode('ascii')))

    key = os.urandom(BLOCK_SIZE)
    print ('Encryption key :', key)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    encoded = EncodeAES(cipher, message)
    print ('Encrypted Pesan :', encoded)

def decryption(encryptedString):
    
    PADDING = '{'
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e).decode('ascii')).rstrip(PADDING)
    key = input('Masukan Key : ')
    cipher = AES.new(key, AES.MODE_CBC)
    decoded = DecodeAES(cipher, encryptedString)
    print (decoded)


if __name__=='__main__':
    print('-------------------------')
    print('Enkripsi & Dekripsi Program')
    print('By : Ganesh Rangga Saputra')
    print('-------------------------')
    print('1. Enkripsi\n2. Dekripsi\n------------------------')
    pilihan = int(input('Pilih mode : '))
    if pilihan == 1 : 
           message = input('Masukan Pesan : ')
           print(encryption(message))
    elif pilihan == 2 :
          e = input('Masukan Pesan : ')
          print(decryption(e))
    else :
        print('Tidak Ada')
