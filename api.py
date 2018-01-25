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

# Escapes certain characters that would otherwise cause SQL errors
def sql_sanitise(data):
    return data.replace("\\","\\\\").replace("'","\\'").replace(";","\\;").replace("_","\\_").replace("%","\\%")

# Returns the size an string of length `data_size` would be if padded and AES encrypted
def get_AES_size(data_size):
    return 16*((data_size/16)+1)

# Allows a client to check the status of the database
# Good for things such as setup procedures
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

# Requires an administrative user and password for the SQL server
# You could use the root user, but I would recommend using a dedicated user
# This user can be limited just to this database, which would make your server more secure
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
            cur.execute("CREATE DATABASE {database};".format(**{"database":sql_sanitise(DATABASE_NAME)}))
            cur.close()
            db.commit()
            db.close()
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
                    "(Username VARBINARY({max_username_chars}) PRIMARY KEY NOT NULL,".format(**{"max_username_chars":get_AES_size(MAX_USERNAME_CHARS)})+\
                    "Forename VARBINARY({max_forename_length}),".format(**{"max_forename_length":get_AES_size(MAX_FORENAME_LENGTH)})+\
                    "Surname VARBINARY({max_surname_length}));".format(**{"max_surname_length":get_AES_size(MAX_SURNAME_LENGTH)}))
        db.commit()

        #Username, report are encrypted
        cur.execute("CREATE TABLE Incidents "+\
                    "(IncidentID INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,"+\
                    "Username VARBINARY({max_username_chars}) NOT NULL,".format(**{"max_username_chars":get_AES_size(MAX_USERNAME_CHARS)})+\
                    "Report BLOB,"+\
                    "Date DATE,"+\
                    "FOREIGN KEY (Username) REFERENCES Students(Username));")
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
                    "(Login VARCHAR({max_login_length}) PRIMARY KEY NOT NULL,".format(**{"max_login_length":MAX_LOGIN_LENGTH})+\
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
                    "(Login VARCHAR({max_login_length}) NOT NULL,".format(**{"max_login_length":MAX_LOGIN_LENGTH})+\
                    "FileID VARCHAR({max_username_chars}) NOT NULL,".format(**{"max_username_chars":MAX_USERNAME_CHARS})+\
                    "DecryptionKey BLOB NOT NULL,"+\
                    "PRIMARY KEY (Login, FileID));")
        # File will either be a student's username (for their photo) or a short reference meaning the database
        # Always 256 because 2048 bit RSA key
        # BLOB must be used because an RSA encrypted value is 256 bytes (exceeding the BINARY maximum of 255)
        db.commit()
        cur.close()
        #except MySQLdb.ProgrammingError:
        #    print "Table 'FileKeys' already exists!"
        
    except Exception,e:
        return json.dumps({"status":"BAD","error":"Failed to set up database!","data":str(e)})

    #After setting up the database, an administrator user must be created
    #First, a password is needed
    chars = string.letters + string.digits + string.punctuation
    adminpw = "".join([chars[random.randrange(0,len(chars))] for i in range(12)]) # generate a secure admin password

    key = add_new_account("admin",adminpw,0,db)

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
    db = MySQLdb.connect(host=hostname,
                             user=user,
                             passwd=passwd,
                             db=DATABASE_NAME)
    cur = db.cursor()
    cur.execute("INSERT INTO FileKeys VALUES ("+\
                "'admin',\n"+\
                "'+database',\n"+\
                "'{key}');".format(**{"key":str(s_encrypted_key)}))
    db.commit()
    cur.close()
    db.close()

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

    #The hash is sanitised
    s_pwhash = sql_sanitise(pwhash)

    cur = db.cursor()
    cur.execute("INSERT INTO Accounts(Login,PasswordHash,PublicKey,PrivateKey,AccountType) VALUES "+\
                "('{username}',\n".format(**{"username":username})+\
                "'{hash}',\n".format(**{"hash":s_pwhash})+\
                "'{public_RSA}',\n".format(**{"public_RSA":key.publickey().exportKey()})+\
                "AES_ENCRYPT('{RSA}','{AES}'),\n".format(**{"RSA":sql_sanitise(exported),"AES":sql_sanitise(aes_key)})+\
                "{level})".format(**{"level":level}))
    cur.close()
    db.commit()
    db.close()
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
    if cur.execute("SELECT PasswordHash FROM Accounts WHERE Login = '{user}';".format(**{"user":sql_sanitise(user)})) != 1:
        return json.dumps({"status":"BAD","error":"Incorrect username/password."})
    server_h = cur.fetchall()[0][0]
    cur.close()
    db.close()

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
    r.set_cookie("Username",value=user)
    return r

# It would be advantageous to write a function for getting the user's private key
# This is an essential part of accessing the database
def get_private_key(request):
    try:
        sql_cfg = configman.read("config/SQLusers.cnf")
    except:
        return (False,json.dumps({"status":"BAD","error":"Failed to load config."}))
    
    # Get the username and encrypted AES key from the cookies
    username = str(request.cookies.get("Username"))
    e_key = request.cookies.get("API_SESSION").decode("hex")
    if username == "None" or e_key == None:
        return (False,json.dumps({"status":"BAD","error":"Invalid authentication cookie. Please login again."}))
    
    # Load the server RSA key
    f = open("config/key.rsa")
    server_rsa = RSA.importKey(f.read())
    f.close()

    # Decrypt the AES key
    key = server_rsa.decrypt(e_key)

    # Connect to the database
    db = MySQLdb.connect(host=sql_cfg["host"],
                         user=sql_cfg["SQLaccount"],
                         passwd=sql_cfg["SQLpassword"],
                         db=sql_cfg["DATABASE_NAME"])
    cur = db.cursor()
    if cur.execute("SELECT AES_DECRYPT(PrivateKey,'{AES}') FROM Accounts WHERE Login = '{username}';".format(**{"AES":sql_sanitise(key),"username":sql_sanitise(username)})) != 1:
        return (False,json.dumps({"status":"BAD","error":"Invalid authentication cookie. Please login again."}))
    try:
        rsa = RSA.importKey(cur.fetchall()[0][0])
        cur.close()
        db.close()
    except ValueError:
        cur.close()
        db.close()
        return (False,json.dumps({"status":"BAD","error":"Invalid authentication cookie. Please login again."}))
    return (True,rsa)

# We can use the function from above to construct a function for getting the AES key of a file
def get_file_key(user,RSA_key,File="+database"):
    try:
        sql_cfg = configman.read("config/SQLusers.cnf")
    except:
        return json.dumps({"status":"BAD","error":"Failed to load config."})

    # Log into the database and retrieve the encrypted AES key for the database
    db = MySQLdb.connect(host=sql_cfg["host"],
                         user=sql_cfg["SQLaccount"],
                         passwd=sql_cfg["SQLpassword"],
                         db=sql_cfg["DATABASE_NAME"])
    cur = db.cursor()
    if cur.execute("SELECT DecryptionKey FROM FileKeys WHERE FileID = '+database' AND Login = '{user}';".format(**{"user":sql_sanitise(user)})) != 1:
        return json.dumps({"status":"BAD","error":"No access to file."})
    e_aes_key = cur.fetchall()[0][0]
    cur.close()
    db.close()

    # Decrypt the key
    aes_key = RSA_key.decrypt(e_aes_key)
    return aes_key

@api.route("add_new_student")
def add_new_student(request):
    try:
        sql_cfg = configman.read("config/SQLusers.cnf")
    except:
        return json.dumps({"status":"BAD","error":"Failed to load config."})
    if not request.cookies.has_key("Username"):
        return json.dumps({"status":"BAD","error":"Invalid authentication cookie. Please login again."})
    user = str(request.cookies.get("Username"))
    if not (request.form.has_key("user")):
        return json.dumps({"status":"BAD","error":"Missing username."})
    else:
        student = str(request.form["user"].lower())
    if request.form.has_key("forename"):
        forename = str(request.form["forename"])
    else:
        forename = None
    if request.form.has_key("surname"):
        surname = str(request.form["surname"])
    else:
        surname = None

    # Get the user's private key.
    key = get_private_key(request)
    if key[0] == False:
        return key[1]
    key = key[1]

    # Get the database AES key
    aes_key = get_file_key(user,key)

    # Generate the query -- no point inserting a forename/surname if we don't know it
    data = {"forename":"","surname":""}
    if forename != None:
        data["forename"] = ",Forename"
    if surname != None:
        data["surname"] = ",Surname"
    query = "INSERT INTO Students(Username{forename}{surname}) VALUES (AES_ENCRYPT('".format(**data)
    data = {"key":sql_sanitise(aes_key),"forename":"","surname":""}
    if forename != None:
        data["forename"] = ",AES_ENCRYPT('"+sql_sanitise(forename)+"','"+sql_sanitise(aes_key)+"')"
    if surname != None:
        data["surname"] = ",AES_ENCRYPT('"+sql_sanitise(surname)+"','"+sql_sanitise(aes_key)+"')"
    query += sql_sanitise(student)+"','{key}'){forename}{surname});".format(**data)

    db = MySQLdb.connect(host=sql_cfg["host"],
                         user=sql_cfg["SQLaccount"],
                         passwd=sql_cfg["SQLpassword"],
                         db=sql_cfg["DATABASE_NAME"])
    cur = db.cursor()
    try:
        cur.execute(query)
    except MySQLdb.IntegrityError:
        return json.dumps({"status":"BAD","error":"User already exists!"})
    db.commit()
    cur.close()
    db.close()
    return json.dumps({"status":"OK"})

@api.route("student_query")
def student_query(request):
    try:
        sql_cfg = configman.read("config/SQLusers.cnf")
    except:
        return json.dumps({"status":"BAD","error":"Failed to load config."})
    if not request.cookies.has_key("Username"):
        return json.dumps({"status":"BAD","error":"Invalid authentication cookie. Please login again."})
    user = str(request.cookies.get("Username"))
    if request.form.has_key("filter"):
        try:
            Filter = json.loads(request.form["filter"])
        except ValueError:
            Filter = None
    else:
        Filter = None

    # Get the user's private key
    key = get_private_key(request)
    if key[0] == False:
        return key[1]
    key = key[1]

    # Get the database AES key
    aes_key = get_file_key(user,key)

    # Generate the query based on whether there is a filter or not
    query = "SELECT AES_DECRYPT(Username,'{AES}'),AES_DECRYPT(Forename,'{AES}'),AES_DECRYPT(Surname,'{AES}') FROM Students".format(**{"AES":sql_sanitise(aes_key)})
    if Filter:
        where = False
        like = False
        if Filter.has_key("like"):
            if Filter["like"]:
                like = True
        if Filter.has_key("user"):
            if where == False:
                query += " WHERE "
                where = True
            else:
                query += " AND "
            if like:
                query += "AES_DECRYPT(Username,'{AES}') LIKE '%{user}%'".format(**{"user":sql_sanitise(str(Filter["user"])).lower(),"AES":sql_sanitise(aes_key)})
            else:
                query += "AES_DECRYPT(Username,'{AES}') = '{user}'".format(**{"user":sql_sanitise(str(Filter["user"])).lower(),"AES":sql_sanitise(aes_key)})
        if Filter.has_key("forename"):
            if where == False:
                query += " WHERE "
                where = True
            else:
                query += " AND "
            if like:
                query += "LOWER(AES_DECRYPT(Forename,'{AES}')) LIKE '%{forename}%'".format(**{"forename":sql_sanitise(str(Filter["forename"])).lower(),"AES":sql_sanitise(aes_key)})
            else:
                query += "LOWER(AES_DECRYPT(Forename,'{AES}')) = '{forename}'".format(**{"forename":sql_sanitise(str(Filter["forename"])).lower(),"AES":sql_sanitise(aes_key)})
        if Filter.has_key("surname"):
            if where == False:
                query += " WHERE "
                where = True
            else:
                query += " AND "
            if like:
                query += "LOWER(AES_DECRYPT(Surname,'{AES}')) LIKE '%{surname}%'".format(**{"surname":sql_sanitise(str(Filter["surname"])).lower(),"AES":sql_sanitise(aes_key)})
            else:
                query += "LOWER(AES_DECRYPT(Surname,'{AES}')) = '{surname}'".format(**{"surname":sql_sanitise(str(Filter["surname"])).lower(),"AES":sql_sanitise(aes_key)})

    # Connect to the database and run the query
    db = MySQLdb.connect(host=sql_cfg["host"],
                         user=sql_cfg["SQLaccount"],
                         passwd=sql_cfg["SQLpassword"],
                         db=sql_cfg["DATABASE_NAME"])
    cur = db.cursor()
    cur.execute(query)
    data = cur.fetchall()
    cur.close()
    db.close()

    return json.dumps({"status":"OK","data":data})
    
api.start()
