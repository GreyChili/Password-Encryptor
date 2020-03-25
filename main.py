import  argparse, bcrypt
# pip install argparse and bcrypt

parser = argparse.ArgumentParser(description="Encrypt passwords with bcrypt")
parser.add_argument("-p", "--password", type=str, metavar="", required=True, help="Password to encrypt")
parser.add_argument("-f", "--file", type=str, metavar="", required=False, help="Save password to given file")
parser.add_argument("-c", "--compare", type=str, metavar="", required=False, help="Compare password with an encrypted string")
group = parser.add_mutually_exclusive_group()
group.add_argument("-q", "--quiet", action="store_true", help="print quiet")
group.add_argument("-v", "--verbose", action="store_true", help="print verbose")
args = parser.parse_args()

def Compare(inputPass, targetPassEncrypted):

    if bcrypt.checkpw(inputPass.encode(), targetPassEncrypted):
        return True
    else:
        return False

def Encrypt(unencryptedPass):

    unencryptedPass = unencryptedPass.encode()
    encryptedPass = bcrypt.hashpw(unencryptedPass, bcrypt.gensalt())
    encryptedPass = encryptedPass.decode()

    return encryptedPass

if __name__ == "__main__":
    encyptedPass = Encrypt(args.password)

    if args.file != None:
        f = open(args.file, "w")
        f.write(encyptedPass)
    else:
        pass

    

    message = None

    if args.quiet:
        message = encyptedPass
    elif args.verbose:
        message = "Unencrypted password is:\n%s\nEncrypted password is:\n%s" %(args.password, encyptedPass)
    elif args.compare != None:
        if Compare(args.password, args.compare):
            message = "Password "
    else:
        message = "Encrypted password is:\n%s" % (encyptedPass)

    print(message)