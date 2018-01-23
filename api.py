##API for a prefect ban management system

import apiframework
import MySQLdb
import os
import json
import configman
import string
import random
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

app = apiframework.app
api = apiframework.API()

def sql_sanitise(data):
    return data.replace("\\","\\\\").replace("'","\\'").replace(";","\\;").replace("_","\\_").replace("%","\\%")

def get_AES_size(data_size):
    return 16*((data_size/16)+1)

@api.route("status")
def status():
    data = {}
    if "SQLusers.cnf" not in os.listdir("config"):
        data["initialised"] = False
    elif int(configman.read("config/SQLusers.cnf")["initialised"]) == 0:
        data["initialised"] = False
    else:
        data["initialised"] = True
    return json.dumps({"status":"OK","data":data})

@api.route("init")
def initialise(request):
    if "SQLusers.cnf" in os.listdir("config"):
        if configman.read("config/SQLusers.cnf")["initialised"] != 0:
            return json.dumps({"status":"BAD","data":"Already initialised!"})
    try:
        defaults = configman.read("config/defaults.cnf")
        DATABASE_NAME = defaults["DATABASE_NAME"]
        MAX_USERNAME_CHARS = int(defaults["MAX_USERNAME_CHARS"])
        MAX_FORENAME_LENGTH = int(defaults["MAX_FORENAME_LENGTH"])
        MAX_SURNAME_LENGTH = int(defaults["MAX_SURNAME_LENGTH"])
        MAX_LOGIN_LENGTH = int(defaults["MAX_LOGIN_LENGTH"])
        # Converting to INT acts as a form of SQL Injection prevention

        if not (request.form.has_key("user") and request.form.has_key("pass")):
            return json.dumps({"status":"BAD","error":"Missing username and/or password."})
        else:
            user = request.form["user"]
            passwd = request.form["pass"]
        if not (request.form.has_key("host")):
            hostname = "localhost"
        else:
            hostname = request.form["host"]
    except Exception,e:
        return json.dumps({"status":"BAD","error":"Failed to load config!","data":str(e)})
    try:
        # Firstly, we want to generate an RSA key for the server
        # This will be used to encrypt user cookies
        # While security is slightly compromised if the server is compromised (if the hacker also has access to a valid cookie, they could decrypt this to gain access to the database)
        # This is a very minor drop in security, and as soon as the breach is detected it can be solved by generating a new server key
        server_rsa = RSA.generate(2048)
        f = open("config/key.rsa","w")
        f.write(server_rsa.exportKey())
        f.close()
    except Exception,e:
        return json.dumps({"status":"BAD","error":"Failed to generate key!","data":str(e)})
    try:
        # Log into the server and create the new database
        try:
            db = MySQLdb.connect(host=hostname,
                                 user=user,
                                 passwd=passwd)
            cur = db.cursor()
            cur.execute("CREATE DATABASE "+DATABASE_NAME+";")
            db.commit()
        except MySQLdb.ProgrammingError:
            print "Database already exists!"

        # Log in, using the new database, and create the tables
        db = MySQLdb.connect(host=hostname,
                             user=user,
                             passwd=passwd,
                             db=DATABASE_NAME)
        cur = db.cursor()

        #AES size = 16*((len(string)/16)+1)

        #Username, forename, surname are encrypted
        cur.execute("CREATE TABLE Students "+\
                    "(UserID INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,"
                    "Username VARBINARY("+str(get_AES_size(MAX_USERNAME_CHARS))+") NOT NULL,"+\
                    "Forename VARBINARY("+str(get_AES_size(MAX_FORENAME_LENGTH))+"),"+\
                    "Surname VARBINARY("+str(get_AES_size(MAX_SURNAME_LENGTH))+"));")
        db.commit()

        #Username, report are encrypted
        cur.execute("CREATE TABLE Incidents "+\
                    "(IncidentID INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,"+\
                    "UserID INTEGER NOT NULL,"+\
                    "Report BLOB,"+\
                    "Date DATE,"+\
                    "FOREIGN KEY (UserID) REFERENCES Students(UserID));")
        db.commit()

        #Sanction is encrypted
        cur.execute("CREATE TABLE Sanctions "+\
                    "(SanctionID INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,"+\
                    "StartDate DATE,"+\
                    "EndDate DATE,"+\
                    "Sanction TEXT,"+\
                    "IncidentID INTEGER,"+\
                    "FOREIGN KEY (IncidentID) REFERENCES Incidents(IncidentID));")
        db.commit()

        cur.execute("CREATE TABLE Accounts "+\
                    "(Login VARCHAR("+str(MAX_LOGIN_LENGTH)+") PRIMARY KEY NOT NULL,"+\
                    "PasswordHash BINARY(32) NOT NULL,"+\
                    "PublicKey TEXT NOT NULL,"+\
                    "PrivateKey BLOB NOT NULL,"+\
                    "AccountType INTEGER NOT NULL,"+\
                    "Email VARCHAR(254));")
        #TEXT is used as these fields exceed 255 chars
        #The hash can be stored efficiently in a BINARY field
        #The private key is best stored in a BLOB. This allows the AES-enrypted private key to be stored as a binary object so as to be space-efficient. Also very compatible with the AES_ENCRYPT function of MySQL
        #254 is the standard max email length
        db.commit()

        #try:
        cur.execute("CREATE TABLE FileKeys "+\
                    "(Login VARCHAR("+str(MAX_LOGIN_LENGTH)+") NOT NULL,"+\
                    "FileID VARCHAR("+str(MAX_USERNAME_CHARS)+") NOT NULL,"+\
                    "DecryptionKey BLOB NOT NULL,"+\
                    "PRIMARY KEY (Login, FileID));")
        # File will either be a student's username (for their photo) or a short reference meaning the database
        # Always 256 because 2048 bit RSA key
        # BLOB must be used because an RSA encrypted value is 256 bytes (exceeding the BINARY maximum of 255)
        db.commit()
        #except MySQLdb.ProgrammingError:
        #    print "Table 'FileKeys' already exists!"
        
    except Exception,e:
        return json.dumps({"status":"BAD","error":"Failed to set up database!","data":str(e)})

    #After setting up the database, an administrator user must be created
    #First, a password is needed
    chars = string.letters + string.digits + string.punctuation
    adminpw = "".join([chars[random.randrange(0,len(chars))] for i in range(12)]) # generate a secure admin password

    key = add_new_account("admin",adminpw,db)

    #After this, we need to generate a random AES key for the database
    #The random range I have chosen generates a 256 bit key

    database_key = random.randrange(57896044618658097711785492504343953926634992332820282019728792003956564819968,
                                    115792089237316195423570985008687907853269984665640564039457584007913129639936)
    
    #This key is converted to hexadecimal, then encrypted with the administrator's key
    encrypted_key = key.encrypt(hex(database_key)[2:].replace("L",""),0)[0]

    #Make sure to sanitise
    s_encrypted_key = sql_sanitise(encrypted_key)

    #This must then be stored in the admin's FileKeys
    #We will identify that this is a database and not a username by including a "+" at the start of the name. This character is illegal in Windows usernames.
    cur = db.cursor()
    cur.execute("INSERT INTO FileKeys VALUES ("+\
                "'admin',\n"+\
                "'+database',\n"+\
                "'"+str(s_encrypted_key)+"');")
    db.commit()

    #This key can then be used for encrypting data in the database
    
    try: # The person setting up the system should be aware that their SQL username and password will be stored as these are essential to the function of the program
        configman.write("config/SQLusers.cnf",
                        {"initialised":"1",
                         "SQLaccount":user,
                         "SQLpassword":passwd,
                         "host":hostname,
                         "DATABASE_NAME":DATABASE_NAME})
    except Exception,e:
        return json.dumps({"status":"BAD","error":"Failed to write config!","data":str(e)})
    return json.dumps({"status":"OK","data":{"initialised":True,"password":adminpw}})

def add_new_account(username,password,db):
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
    while len(exported) % 16 != 0:
        exported += "\0"

    #This is then encrypted by the MySQL server using AES_ENCRYPT
    #It can then be decrypted again using AES_DECRYPT

    #The hash is sanitised
    s_pwhash = sql_sanitise(pwhash)

    cur = db.cursor()
    cur.execute("INSERT INTO Accounts(Login,PasswordHash,PublicKey,PrivateKey,AccountType) VALUES "+\
                "('admin',\n"+\
                "'"+s_pwhash+"',\n"+\
                "'"+key.publickey().exportKey()+"',\n"+\
                "AES_ENCRYPT('"+exported+"','"+aes_key+"'),\n"+\
                "0)")
    db.commit()
    return key

# The login procedure will generate the AES key required to decrypt the user's private key
# This will then be encrypted using the server key, and a HTTP header is sent to instruct the browser to store it in a cookie
# Subsequent requests to the server will contain this cookie and can be decrypted, allowing the server to decrypt the private key and access the data
@api.route("login")
def user_login(request):
    try:
        sql_cfg = configman.read("config/SQLusers.cnf")
    except:
        return json.dumps({"status":"BAD","error":"Failed to load config."})
    if not (request.form.has_key("user") and request.form.has_key("pass")):
        return json.dumps({"status":"BAD","error":"Missing username and/or password."})
    else:
        user = str(request.form["user"].lower())
        passwd = str(request.form["pass"])

    # Log into the SQL database
    db = MySQLdb.connect(host=sql_cfg["host"],
                         user=sql_cfg["SQLaccount"],
                         passwd=sql_cfg["SQLpassword"],
                         db=sql_cfg["DATABASE_NAME"])

    # Hash the password provided
    hasher = SHA256.new()
    hasher.update(passwd)
    h = hasher.digest()

    # Get the hash stored in the database and compare the hashes
    cur = db.cursor()
    # If no results are returned, the account doesn't exist
    if cur.execute("SELECT PasswordHash FROM Accounts WHERE Login = '"+sql_sanitise(user)+"';") != 1:
        return json.dumps({"status":"BAD","error":"Incorrect username/password."})
    server_h = cur.fetchall()[0][0]

    # If the hashes are not equal, the password is incorrect
    if h != server_h:
        return json.dumps({"status":"BAD","error":"Incorrect username/password."})
    
    # Now we must generate the key for decrypting the private key
    hasher = SHA256.new()
    hasher.update(user+passwd+h)
    aes_key = hasher.digest()

    # Now we have to load the server RSA key so we can encrypt our aes key
    f = open("config/key.rsa")
    server_rsa = RSA.importKey(f.read())
    f.close()

    # This will encrypt our key. We also encode it as a hexadecimal string to make sending it "cleaner"
    aes_key = server_rsa.encrypt(aes_key,0)[0].encode("hex")
    
    # Now we set up a response that will instruct the browser to store this cookie
    r = app.make_response(json.dumps({"status":"OK"}))
    r.set_cookie("API_SESSION",value=aes_key)
    return r
    
api.start()
