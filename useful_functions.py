##Useful functions

from specialexceptions import *
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import json
import MySQLdb
import configman


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
        rsa = RSA.importKey(cur.fetchall()[0][0])
        cur.close()
        db.close()
    except ValueError:
        cur.close()
        db.close()
        raise AuthenticationError
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
    cur.close()
    db.close()

    # Decrypt the key
    aes_key = RSA_key.decrypt(e_aes_key)
    return aes_key
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
