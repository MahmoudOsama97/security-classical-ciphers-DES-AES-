import numpy as np



#caeser function
def caeser(plain,k):
    plain = plain.upper()
    ciphertext = str()
    for char in plain:
        ciphertext += chr(((ord(char) - ord('A') + k) % 26) + ord('A'))
    return ciphertext
    
    

    
#playfair function 



def playfair(plainText,key):
    key = key.upper()
    plainText = str(plainText).upper().replace("J","I")
    KeyMatrix = dict() # represent the order of each letter in the key matrix if it was 1D
    index = 0# the index of the current letter in the KeyMatrix
    letters = ""

    for k in key:
        if(k not in KeyMatrix):
            letters+=k
            KeyMatrix[k] = index
            index += 1

    for i in range(ord("A"),ord("Z") + 1):
        if(i == ord("J")):
            continue
        if(chr(i) not in KeyMatrix):
            KeyMatrix[chr(i)] = index
            letters+=chr(i)
            index += 1

    P = list()
    i = 0
    while i < len(plainText):
        if i == len(plainText) - 1: # only last letter left
            if(plainText[i] == "X"): # if the single letter is x append z
                P.append(("X","z"))
            else: # if last letter not x append x
                P.append((plainText[i],"X")) 
        elif plainText[i] == plainText[i+1]: # letter is same as next one
            P.append((plainText[i],"X")) 
        else:
            P.append((plainText[i],plainText[i+1])) 
            i+=1
        i += 1

    def GI(row,col):
        i = row * 5 + col
        return letters[i]
    def SR(row,col):
        return GI(row,(col+1) % 5)
    def SD(row,col):
        return GI((row + 1) % 5,col)
    def encrypt(pair:tuple):
        r1 = KeyMatrix[pair[0]] // 5 # 0,1,2,3,4 will ll return 0 which is required
        c1 = KeyMatrix[pair[0]] % 5 # 0,5,10 all return 0 which is required
        r2 = KeyMatrix[pair[1]] // 5 # 0,1,2,3,4 will ll return 0 which is required
        c2 = KeyMatrix[pair[1]] % 5 # 0,5,10 all return 0 which is required
        ans = str()
        if r1 == r2:
            ans += SR(r1,c1)
            ans += SR(r2,c2)
        elif c1 == c2:
            ans += SD(r1,c1)
            ans += SD(r2,c2)
            pass
        else:
            ans += GI(r1,c2)
            ans += GI(r2,c1)
        return ans
    CipherText = ""
    for i in P:
        CipherText += encrypt(i)
    return CipherText

#hill cipher

def hill(plainText, key, size):
    plainText = plainText.upper()
    plainText += "X" * ((size-len(plainText) % size) % size)
    P = list()
    for i in range(0,len(plainText),size):
        TL = list()
        for j in range(0,size):
            TL.append(ord(plainText[i + j]) - ord("A"))
        P.append(np.array(TL))
    cipherText = ""
    for i in range(0,P.__len__()):
        P[i] = np.dot(key,P[i]) 
        for i in P[i]:
            cipherText += chr((((i%26) + 26) % 26) + ord("A"))
    return cipherText
    
    
#vigenere cipher fuction  
def vigenere(plainText,key,mode):
    plainText = plainText.upper()
    key = key.upper()
    if(mode):#automode
        key += plainText
    else:#repeat
        key = key * (len(plainText) // len(key) + 1)
    cipherText = ""
    for i in range(0,len(plainText)):
        cipherText += caeser(plainText[i],ord(key[i]) - ord('A'))
    return cipherText

#vernam cipher fn
def vernam(plainText,key="spartans"):
    k = list()
    for i in key:
        k.append(ord(i) - ord('A'))
    l = len(k)
    cipherText = ""
    for i in range(0,len(plainText)):
        p = (ord(plainText[i]) - ord('A')) ^ k[i % l]
        cipherText += chr(p + ord('A'))
    return cipherText


def rf(fn):
    f = open(fn, "r")
    ans = []
    for p in f.readlines():
        ans.append(p.replace("\n",""))
    return ans
    

def wf(fn, s):
    f = open(fn, "w")
    for st in s:
        f.write(st + "\n")





plainText = rf("caesar_plain.txt") # Caeser
keys = [3,6,12]
cipherText = []
for k in keys:
    cipherText.append("key: " + str(k))
    for p in plainText:
        cipherText.append(caeser(p,k))
    cipherText.append("\n")
wf("caesar_cipher.txt", cipherText)


plainText = rf("vigenere_plain.txt") # Vigenere 
keys = [("PIE",False), ("AETHER", True)] # false for auto mode and true for repeated mode 
cipherText = []
for k in keys:
    cipherText.append("key: " + str(k[0]) + ", mode: " + ("auto mode" if k[1] else "repeating mode"))
    for p in plainText:
        cipherText.append(vigenere(p,k[0],k[1]))
    cipherText.append("\n")
wf("vigenere_cipher.txt", cipherText)

plainText = rf("playfair_plain.txt") # playfair
keys = [ "RATS", "ARCHANGEL"]
cipherText = []
for k in keys:
    cipherText.append("key: " + str(k))
    for p in plainText:
        cipherText.append(playfair(p,k))
    cipherText.append("\n")
wf("playfair_cipher.txt", cipherText)

plainText = rf("vernam_plain.txt") # vernam
keys = ["SPARTANS"]
cipherText = []
for k in keys:
    cipherText.append("key: " + str(k))
    for p in plainText:
        cipherText.append(vernam(p,k))
    cipherText.append("\n")
wf("vernam_cipher.txt", cipherText)

plainText = rf("hill_plain_2x2.txt") # hill_2x2
key = np.array([[5,17],[8,3]])
cipherText = []
for p in plainText:
    cipherText.append(hill(p,key,2))
wf("hill_cipher_2x2.txt", cipherText)

plainText = rf("hill_plain_3x3.txt") # hill_3x3
key = np.array([[2,4,12],[9,1,6],[7,5,3]])
cipherText = []
for p in plainText:
    cipherText.append(hill(p,key,3))
wf("hill_cipher_3x3.txt", cipherText) 
