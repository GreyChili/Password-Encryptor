import bcrypt
# pip install agrparse and bcrypt

class passwordFunctionsBcrypt:
    pass

    def Encrypt(unencryptedPass):
        unencryptedPass = unencryptedPass.encode()
        encryptedPass = bcrypt.hashpw(unencryptedPass, bcrypt.gensalt())
        encryptedPass = encryptedPass.decode()

        return encryptedPass

    def Compare(inputPass, targetPassEncrypted):
        if bcrypt.checkpw(inputPass.encode(), targetPassEncrypted):
            return True
        else:
            return False