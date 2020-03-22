import bcrypt
import  argparse
# pip install agrparse and bcrypt

parser = argparse.ArgumentParser(description="Encrypt passwords with bcrypt")
parser.add_argument("-p", "--password", type=str, metavar="", required=True, help="Password to encrypt")
parser.add_argument("-f", "--file", type=str, metavar="", required=False, help="Save password to given file")
group = parser.add_mutually_exclusive_group()
group.add_argument("-q", "--quiet", action="store_true", help="print quiet")
group.add_argument("-v", "--verbose", action="store_true", help="print verbose")
args = parser.parse_args()

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
    else:
        message = "Encrypted password is:\n%s" % (encyptedPass)

    print(message)