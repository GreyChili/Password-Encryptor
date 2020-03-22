import bcrypt

filePath = input("Enter path to password destination file.\n")

passF = open(filePath, "w+")

test = "test"

print("Password destination file set to:\n%s" %(filePath))

passUnencrypted = input("Enter a password to encrypt:\n")

def Encrypt(unencryptedPass):
    unencryptedPass = unencryptedPass.encode()

    encryptedPass = bcrypt.hashpw(unencryptedPass, bcrypt.gensalt())

    encryptedPass = encryptedPass.decode()

    return encryptedPass

passF.write(Encrypt(passUnencrypted))
passF.close()

print("Done\nEncrypted password in:\n\n%s" %(filePath))