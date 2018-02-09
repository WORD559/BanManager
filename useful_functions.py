##Useful functions

from specialexceptions import *
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from werkzeug.utils import secure_filename
import json
import MySQLdb
import configman
import os
from PIL import Image
from StringIO import StringIO


# Escapes certain characters that would otherwise cause SQL errors
def sql_sanitise(data):
    return data.replace("\\","\\\\").replace("'","\\'").replace(";","\\;").replace("_","\\_").replace("%","\\%")

# Returns the size an string of length `data_size` would be if padded and AES encrypted
def get_AES_size(data_size):
    return 16*((data_size/16)+1)

def get_SQL_config():
    try:
        sql_cfg = configman.read("config/SQLusers.cnf")
    except:
        raise ConfigError
    return sql_cfg

# Adds a new user account to the database
# This does NOT give them their FileKeys
def add_new_account(username,password,level,db):
    level = int(level)
    hasher = SHA256.new()
    hasher.update(password)
    pwhash = hasher.digest() # This generates our password hash to validate the password

    #Now we hash the username + the password + the hash to make an AES key
    hasher = SHA256.new()
    hasher.update(username+password+pwhash)
    aes_key = hasher.digest()

    #Now we generate a new RSA key for this user
    key = RSA.generate(2048)

    #And export the private key, appending NULL to make it compatible with AES
    exported = key.exportKey()
##    while len(exported) % 16 != 0:
##        exported += "\0"

    #This is then encrypted by the MySQL server using AES_ENCRYPT
    #It can then be decrypted again using AES_DECRYPT


    cur = db.cursor()
    cur.execute("INSERT INTO Accounts(Login,PasswordHash,PublicKey,PrivateKey,AccountType) VALUES "+\
                "('{username}',\n".format(**{"username":sql_sanitise(username)})+\
                "UNHEX('{hash}'),\n".format(**{"hash":pwhash.encode("hex")})+\
                "'{public_RSA}',\n".format(**{"public_RSA":sql_sanitise(key.publickey().exportKey())})+\
                "AES_ENCRYPT('{RSA}','{AES}'),\n".format(**{"RSA":sql_sanitise(exported),"AES":sql_sanitise(aes_key)})+\
                "{level})".format(**{"level":level}))
    cur.close()
    db.commit()
    db.close()
    return key

# It would be advantageous to write a function for getting the user's private key
# This is an essential part of accessing the database
def get_private_key(request):
    sql_cfg = get_SQL_config()
    
    # Get the username and encrypted AES key from the cookies
    username = get_username(request)
    e_key = request.cookies.get("API_SESSION").decode("hex")
    if e_key == None:
        raise AuthenticationError
    
    # Load the server RSA key
    f = open("config/key.rsa")
    server_rsa = RSA.importKey(f.read())
    f.close()

    # Decrypt the AES key
    key = server_rsa.decrypt(e_key)

    # Connect to the database
    db = connect_db()
    cur = db.cursor()
    if cur.execute("SELECT AES_DECRYPT(PrivateKey,'{AES}') FROM Accounts WHERE Login = '{username}';".format(**{"AES":sql_sanitise(key),"username":sql_sanitise(username)})) != 1:
        raise AuthenticationError
    try:
        data = cur.fetchall()[0][0]
##        print data
        rsa = RSA.importKey(data)
        cur.close()
        db.close()
    except ValueError:
        cur.close()
        db.close()
        raise AuthenticationError
    #print rsa.exportKey()
    return rsa

# We can also construct a function for getting the AES key of a file
def get_file_key(user,RSA_key,File="+database"):
    sql_cfg = get_SQL_config()

    # Log into the database and retrieve the encrypted AES key for the database
    db = MySQLdb.connect(host=sql_cfg["host"],
                         user=sql_cfg["SQLaccount"],
                         passwd=sql_cfg["SQLpassword"],
                         db=sql_cfg["DATABASE_NAME"])
    cur = db.cursor()
    if cur.execute("SELECT DecryptionKey FROM FileKeys WHERE FileID = '+database' AND Login = '{user}';".format(**{"user":sql_sanitise(user)})) != 1:
        raise FileKeyError
    e_aes_key = cur.fetchall()[0][0]
##    print "ENC2:",e_aes_key.encode("hex")
    cur.close()
    db.close()

    # Decrypt the key
    aes_key = RSA_key.decrypt(e_aes_key)
##    print "HEX2:",aes_key
##    print aes_key.encode("hex")
##    print len(aes_key)
    return aes_key.decode("hex")
# The two functions above are incredibly useful, and will be used in most subsequent functions

def connect_db():
    sql_cfg = get_SQL_config()
    try:
        db = MySQLdb.connect(host=sql_cfg["host"],
                         user=sql_cfg["SQLaccount"],
                         passwd=sql_cfg["SQLpassword"],
                         db=sql_cfg["DATABASE_NAME"])
    except:
        raise DatabaseConnectError
    return db

def get_username(request):
    if not request.cookies.has_key("Username"):
        raise AuthenticationError
    user = str(request.cookies.get("Username"))
    return user

def get_rank(user):
    db = connect_db()
    cur = db.cursor()
    query = "SELECT AccountType FROM Accounts WHERE Login = '{user}';".format(**{"user":sql_sanitise(user)})
    if cur.execute(query) != 1:
        raise AuthenticationError
    return cur.fetchall()[0][0]

def logout(app):
    r = app.make_response(json.dumps({"status":"OK","data":"Logged out!"}))
    r.set_cookie("API_SESSION",value="",expires=0)
    r.set_cookie("Username",value="",expires=0)
    return r

def upload_file(f,ID):
    if not (f.filename.split(".")[-1].lower() in ["png","jpg","gif"]):
        return False
    upload_path = configman.read("config/defaults.cnf")["PHOTO_FOLDER"]
    # Secure name is semi-redundant because of ID, but I want to be safe from stupitidy and dodgy file extensions
    filename = secure_filename(str(ID)+".jpg")
    delete_file(ID)
    im = Image.open(f)
    im = im.convert("RGB")
    encrypt_image(im,upload_path+"/"+filename)
    return True

def delete_file(ID):
    upload_path = configman.read("config/defaults.cnf")["PHOTO_FOLDER"]
    filename = secure_filename(str(ID)+".jpg")
    if os.path.isfile(upload_path+"/"+filename):
        os.remove(upload_path+"/"+filename)

def encrypt_image(im,path):
    # Save the image to a StringIO -- this keeps it in memory, rather than moving it to a temp file
    # This is more secure
    temp = StringIO()
    im.save(temp,"JPEG")

    # Generate a random key
    key = os.urandom(32)
    # Generate an initialisation vector
    IV = os.urandom(16)
    # Set the block cipher mode to CBC -- essential for images
    mode = AES.MODE_CBC
    # Set up our AES encryptor object
    aes = AES.new(key, mode, IV=IV)

    # Add nulls to the end of our file until the length is divisible by 16
    while temp.len % 16 != 0:
        temp.write("\0")

    # Go back to the start of the file... this way we can read out the contents
    temp.seek(0)

    # Now we open our output file and begin to write the encrypted data
    with open(path,"wb") as output:
        # Write our IV so we can use it for decryption later
        output.write(IV)

        # Now we encrypt the file and write it. I'll probably chunk it later.
        output.write(aes.encrypt(temp.read()))

    return key
    # Now it should be giggity good.
        
def decrypt_image(key,path):
    # Open the image and read the IV
    with open(path,"rb") as inp:
        IV = inp.read(16)

    # Make our AES object
    mode = AES.MODE_CBC
    aes = AES.new(key,mode,IV=IV)

    temp = StringIO()
    with open(path,"rb") as inp:
        # Set the cursor position to 16 to skip the IV
        inp.seek(16)

        # Read in the data and decrypt to temp
        temp.write(aes.decrypt(inp.read()))
    im = Image.open(temp)
    return im

    
