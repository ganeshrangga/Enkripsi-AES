from Crypto.Cipher import AES
import numpy as np
from Crypto import Random
import base64
import os

def aes():
    def encryption(message):
        PADDING = '*'
        BLOCK_SIZE = 16
        key = Random.new().read(16)
        iv = Random.new().read(16)
        pad = lambda a: a + (BLOCK_SIZE - len(a) % BLOCK_SIZE) * PADDING
        cipher = AES.new(key, AES.MODE_CBC, iv)
        EncodeAES = base64.b64encode(iv + cipher.encrypt(pad(message).encode('ascii')))
        data = (key,EncodeAES)
        return data

    a = encryption(input('Masukan Pesan : '))
    EncodeAES=a[1]
    key=a[0]
    print('Key : ', key)
    print('Hasil Enkripsi : ',EncodeAES)

    def decryption(key, EncodeAES):
        iv = base64.b64decode(EncodeAES)[:16]
        encrypted_message=base64.b64decode(EncodeAES)[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        DecodeAES = cipher.decrypt(encrypted_message).decode('ascii')
        return DecodeAES.rstrip('*')
    decript= decryption(key, EncodeAES)
    print ('Hasil Dekripsi : ',decript)

def des():
    IP          = (2, 6, 3, 1, 4, 8, 5, 7)
    IP_INVERSE  = (4, 1, 3, 5, 7, 2, 8, 6)
    E           = (4, 1, 2, 3, 2, 3, 4, 1)
    P10         = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
    P8          = (6, 3, 7, 4, 8, 5, 10, 9)
    P4          = (2, 4, 3, 1)
    S0          = np.asarray([1,0,3,2,3,2,1,0,0,2,1,3,3,1,3,2]).reshape(4,4)
    S1          = np.asarray([0,1,2,3,2,0,1,3,3,0,1,0,2,1,0,3]).reshape(4,4)

    KEY   = '0111111101'
    left  = lambda x : x[:len(x)/2]
    right = lambda x : x[len(x)/2:]

    def permutation(original, key):
        return ''.join(original[i-1] for i in key)

    def shift(bit):
        return left(bit)[1:] + left(bit)[0] +\
               right(bit)[1:] + right(bit)[0]
     
    def genfirstKey():
        rotated = shift(permutation(KEY,P10))
        return permutation(rotated, P8)

    def gensecondKey():
        rotated = shift(shift(shift(permutation(KEY,P10))))
        return permutation(rotated, P8)

    def xor(bit, key):
        bit = map(int,bit)
        key = map(int,key)
        return ''.join( str((i+j) % 2) for i,j in zip(bit,key))
        
    def SBox(bit, sbox): 
        row = int(bit[0] + bit[3], 2)
        col = int(bit[1] + bit[2], 2)
        return '{0:02b}'.format(sbox[row][col])

    def Fk(bit, key):
        L,R = left(bit), right(bit)
        bit = xor(permutation(R,E),key)
        bit = SBox(left(bit), S0) + SBox(right(bit), S1)
        bit = permutation(bit, P4)
        return xor(bit, L)

    def encrypt(plain):
        bit = permutation(plain, IP) 
        tmp = Fk(bit, genfirstKey())
        bit = right(bit) + tmp
        bit = Fk(bit, gensecondKey())
        return permutation(bit + tmp, IP_INVERSE)

    def decrypt(enc):
        bit = permutation(enc, IP)
        tmp = Fk(bit, gensecondKey())
        bit = right(bit) + tmp
        bit = Fk(bit, genfirstKey())
        return permutation(bit + tmp, IP_INVERSE)
        
    if __name__ == '__main__':
        _plain = input('Input the plain text: ')
        _encry = lambda x : encrypt(bin(ord(x)).lstrip('-0b').zfill(8)), list(_plain)
        _decry = lambda x : chr(int(decrypt(x),2)), _encry
        _encry = lambda x :  chr(int(x,2))

        print ('Plain text : ', _plain)
        print ('Encrypted  : ', _encry)
        print ('Decrypted  : ', _decry)

if __name__=='__main__':
    print('-------------------------')
    print('Enkripsi & Dekripsi Program')
    print('By : Ganesh Rangga Saputra')
    print('-------------------------')
    print('1. AES\n2. DES\n------------------------')
    pilihan = int(input('Pilih mode : '))
    if pilihan == 1 :
        print('------- ENKRIPSI AES --------')
        aes()
    elif pilihan == 2 :
        print('------- ENKRIPSI DES --------')
        des()
    else :
        print('Tidak Ada')
