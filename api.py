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
        try:
            cur.execute("CREATE TABLE Students "+\
                        "(Username VARCHAR("+str(MAX_USERNAME_CHARS)+") PRIMARY KEY NOT NULL,"+\
                        "Forename VARCHAR("+str(MAX_FORENAME_LENGTH)+"),"+\
                        "Surname VARCHAR("+str(MAX_SURNAME_LENGTH)+"));")
            db.commit()
        except MySQLdb.ProgrammingError:
            print "Table 'Students' already exists!"
        try:
            cur.execute("CREATE TABLE Incidents "+\
                        "(IncidentID INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,"+\
                        "Username VARCHAR("+str(MAX_USERNAME_CHARS)+") NOT NULL,"+\
                        "Report TEXT,"+\
                        "Date DATE,"+\
                        "FOREIGN KEY (Username) REFERENCES Students(Username));")
            db.commit()
        except MySQLdb.ProgrammingError:
            print "Table 'Incidents' already exists!"
        try:
            cur.execute("CREATE TABLE Sanctions "+\
                        "(SanctionID INTEGER PRIMARY KEY NOT NULL AUTO_INCREMENT,"+\
                        "StartDate DATE,"+\
                        "EndDate DATE,"+\
                        "Sanction TEXT,"+\
                        "IncidentID INTEGER,"+\
                        "FOREIGN KEY (IncidentID) REFERENCES Incidents(IncidentID));")
            db.commit()
        except MySQLdb.ProgrammingError:
            print "Table 'Sanctions' already exists!"
        try:
            cur.execute("CREATE TABLE Accounts "+\
                        "(Login VARCHAR("+str(MAX_LOGIN_LENGTH)+") PRIMARY KEY NOT NULL,"+\
                        "PasswordHash BINARY(32) NOT NULL,"+\
                        "PublicKey TEXT NOT NULL,"+\
                        "PrivateKey BLOB NOT NULL,"+\
                        "AccountType INTEGER NOT NULL,"+\
                        "Email VARCHAR(254));")
            #TEXT is used as these fields exceed 255 chars
            #254 is the standard max email length
            db.commit()
        except MySQLdb.ProgrammingError:
            print "Table 'Accounts' already exists!"
        #try:
        cur.execute("CREATE TABLE FileKeys "+\
                    "(Login VARCHAR("+str(MAX_LOGIN_LENGTH)+") NOT NULL,"+\
                    "FileID VARCHAR("+str(MAX_USERNAME_CHARS)+") NOT NULL,"+\
                    "DecryptionKey TEXT NOT NULL,"+\
                    "PRIMARY KEY (Login, FileID));")
        # File will either be a student's username (for their photo) or a short reference meaning the database
        # Always 256 because 2048 bit RSA key
        db.commit()
        #except MySQLdb.ProgrammingError:
        #    print "Table 'FileKeys' already exists!"
        
    except Exception,e:
        return json.dumps({"status":"BAD","error":"Failed to set up database!","data":str(e)})

    #After setting up the database, an administrator user must be created
    #First, a password is needed
    chars = string.letters + string.digits + string.punctuation
    adminpw = "".join([chars[random.randrange(0,len(chars))] for i in range(12)]) # generate a secure admin password
    hasher = SHA256.new()
    hasher.update(adminpw)
    pwhash = hasher.digest() # This generates our password hash to validate the password

    #Now we hash this hash + the original password + the username to make an AES key
    hasher = SHA256.new()
    hasher.update("Admin"+adminpw+pwhash)
    aes_key = hasher.digest()

    #Now we generate a new RSA key for this user
    key = RSA.generate(2048)

    #And export the private key, appending NULL to make it compatible with AES
    exported = key.exportKey()
    while len(exported) % 16 != 0:
        exported += "\0"

    #This is then encrypted by the MySQL server using AES_ENCRYPT
    #It can then be decrypted again using AES_DECRYPT


    cur = db.cursor()
    cur.execute("INSERT INTO Accounts(Login,PasswordHash,PublicKey,PrivateKey,AccountType) VALUES "+\
                "('Admin',\n"+\
                "'"+pwhash+"',\n"+\
                "'"+key.publickey().exportKey()+"',\n"+\
                "AES_ENCRYPT('"+exported+"','"+aes_key+"'),\n"+\
                "0)")
    db.commit()
    
    try:
        configman.write("config/SQLusers.cnf",
                        {"initialised":"1","SQLadmin":user,"host":hostname})
    except Exception,e:
        return json.dumps({"status":"BAD","error":"Failed to write config!","data":str(e)})
    return json.dumps({"status":"OK","data":{"initialised":True,"password":adminpw}})

api.start()
