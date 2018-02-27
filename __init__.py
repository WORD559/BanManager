##API for a prefect ban management system

from flask import Flask
from flask_cors import CORS
import apiframework
from specialexceptions import *
from useful_functions import *
from flask import send_file
import MySQLdb
import os
import json
import configman
import string
import random
import datetime
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

# Make the Flask application for the whole package and pass it to the framework
# This allows the application to be run as a package rather than as modules
# This will ultimately make the execution process easier
# Once the package is installed, the FLASK_APP environment varibale just needs to be set to BanManager, and then `flask run` can be used to start the system
app = Flask(__name__)
CORS(app)
##app = apiframework.app
api = apiframework.API(app)

# Since we're now a package, we need to move our current working directory to the package directory
os.chdir(app.root_path)



# Allows a client to check the status of the database
# Good for things such as setup procedures
@api.route("status")
def status(request):
    data = {}
    if "SQLusers.cnf" not in os.listdir("config"):
        data["initialised"] = False
    elif int(configman.read("config/SQLusers.cnf")["initialised"]) == 0:
        data["initialised"] = False
    else:
        data["initialised"] = True
    try:
        get_private_key(request) # This will let me check to see if they're logged in
        data["logged_in"] = True
        data["user"] = get_username(request)
        data["rank"] = get_rank(data["user"])
    except AuthenticationError:
        data["logged_in"] = False
        data["user"] = None
        data["rank"] = None
    return json.dumps({"status":"OK","data":data})

# Requires an administrative user and password for the SQL server
# You could use the root user, but I would recommend using a dedicated user
# This user can be limited just to this database, which would make your server more secure
@api.route("init",["POST"])
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
        raise ConfigError
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
                    "Surname VARBINARY({max_surname_length}),".format(**{"max_surname_length":get_AES_size(MAX_SURNAME_LENGTH)})+\
                    "PhotoID INTEGER NOT NULL AUTO_INCREMENT UNIQUE);")
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
                    "Sanction BLOB,"+\
                    "IncidentID INTEGER,"+\
                    "FOREIGN KEY (IncidentID) REFERENCES Incidents(IncidentID));")
        db.commit()

        cur.execute("CREATE TABLE Accounts "+\
                    "(Login VARCHAR({max_login_length}) PRIMARY KEY NOT NULL,".format(**{"max_login_length":MAX_LOGIN_LENGTH})+\
                    "PasswordHash BINARY(32) NOT NULL,"+\
                    "Salt BINARY(8) NOT NULL,"+\
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
##    print key.exportKey()

    #After this, we need to generate a random AES key for the database
    #We will use os.urandom, as this is more secure for cryptographic purposes

    database_key = os.urandom(32)
##    print "RAW:",database_key
    #This key is converted to hexadecimal, then encrypted with the administrator's key
    #The encrypted key is put in hex, and then entered using MySQL's UNHEX
    #This is to overcome an odd problem I was having where the encrypted string stored in the database was wrong
    hex_key = database_key.encode("hex")
##    print "HEX:",hex_key
    encrypted_key = key.encrypt(hex_key,0)[0].encode("hex")
##    print "ENC:",encrypted_key

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
                "UNHEX('{key}'));".format(**{"key":str(s_encrypted_key)}))
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
        raise ConfigError
    return json.dumps({"status":"OK","data":{"initialised":True,"password":adminpw}})


# The login procedure will generate the AES key required to decrypt the user's private key
# This will then be encrypted using the server key, and a HTTP header is sent to instruct the browser to store it in a cookie
# Subsequent requests to the server will contain this cookie and can be decrypted, allowing the server to decrypt the private key and access the data
@api.route("login",["POST"])
def user_login(request):
    #sql_cfg = get_SQL_config()
    if not (request.form.has_key("user") and request.form.has_key("pass")):
        return json.dumps({"status":"BAD","error":"Missing username and/or password."})
    else:
        user = str(request.form["user"].lower())
        passwd = str(request.form["pass"])

    # Log into the SQL database
    db = connect_db()

    # Get the hash stored in the database and compare the hashes
    cur = db.cursor()
    # If no results are returned, the account doesn't exist
    if cur.execute("SELECT PasswordHash,Salt FROM Accounts WHERE Login = '{user}';".format(**{"user":sql_sanitise(user)})) != 1:
        return json.dumps({"status":"BAD","error":"Incorrect username/password."})
    server_h,salt = cur.fetchall()[0]
    cur.close()
    db.close()

    # Hash the password provided
    hasher = SHA256.new()
    hasher.update(salt+passwd)
    h = hasher.digest()

    # If the hashes are not equal, the password is incorrect
    if h != server_h:
        return json.dumps({"status":"BAD","error":"Incorrect username/password."})

    # Generate an unsalted hash for the key
    hasher = SHA256.new()
    hasher.update(passwd)
    h = hasher.digest()
    
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

# This function is for adding a new student to the database.
# The student's username is required, but their forename and surname are optional
@api.route("add_new_student",["POST"])
def add_new_student(request):
    #sql_cfg = get_SQL_config()
    user = get_username(request)
    if get_rank(user) > 2: # If not a prefect
        raise RankError
    if not (request.form.has_key("user")):
        return json.dumps({"status":"BAD","error":"Missing username."})
    else:
        student = str(request.form["user"].lower()).replace(" ","_")
    if request.form.has_key("forename"):
        forename = str(request.form["forename"])
    else:
        forename = None
    if request.form.has_key("surname"):
        surname = str(request.form["surname"])
    else:
        surname = None
    if request.files.has_key("photo"):
        photo = request.files["photo"]
    else:
        photo = None

    # Get the user's private key.
    key = get_private_key(request)

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
    query += sql_sanitise(student,underscore=False,percent=False)+"','{key}'){forename}{surname});".format(**data)

    db = connect_db()
    cur = db.cursor()
    try:
        cur.execute(query)
    except MySQLdb.IntegrityError:
        raise RecordExistsError
    db.commit()
    photoID = get_photoID(sql_sanitise(student),sql_sanitise(aes_key),cur)
    
    
    if photo != None:
        filekey = upload_file(photo,photoID,db,cur)
        if not filekey:
            return json.dumps({"status":"OK","error":"Failed to upload photo."})
        else:
            # We need to encrypt this key and give every user access to it
            add_new_filekey(photoID,filekey,db,cur)
    cur.close()
    db.close()
    return json.dumps({"status":"OK"})

# This route allows the database to be queried, returning the decoded content of the database
# A json-encoded dictionary filter is optional, otherwise all users are selected
# The filter could contain "user", "forename", "surname", and a boolean "like"
# If "like" is false, the search strings must match
# If "like" is true, records containing your search string are returned
@api.route("query_student",["GET"])
def student_query(request):
    #sql_cfg = get_SQL_config()
    user = get_username(request)
    Filter = {}
    try:
        if request.args.has_key("user"):
            Filter["user"] = str(request.args["user"]).lower().split(" ")
        if request.args.has_key("forename"):
            Filter["forename"] = str(request.args["forename"]).lower()
        if request.args.has_key("surname"):
            Filter["surname"] = str(request.args["surname"]).lower()
        if request.args.has_key("like"):
            Filter["like"] = bool(request.args["like"])

    except:
        return json.dumps({"status":"BAD","error":"Invalid arguments."})
    

    # Get the user's private key
    key = get_private_key(request)

    # Get the database AES key
    aes_key = get_file_key(user,key)

    # Generate the query based on whether there is a filter or not
    query = "SELECT AES_DECRYPT(Username,'{AES}'),AES_DECRYPT(Forename,'{AES}'),AES_DECRYPT(Surname,'{AES}') FROM Students".format(**{"AES":sql_sanitise(aes_key)})

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
        query+= "("
        OR = False
        for user in Filter["user"]:
            if OR:
                query+= " OR "
            else:
                OR = True
            if like:
                query += "AES_DECRYPT(Username,'{AES}') LIKE '%{user}%'".format(**{"user":sql_sanitise(user,underscore=False,percent=False),"AES":sql_sanitise(aes_key)})
            else:
                query += "AES_DECRYPT(Username,'{AES}') = '{user}'".format(**{"user":sql_sanitise(user,underscore=False,percent=False),"AES":sql_sanitise(aes_key)})
        query+=")"
    # Weirdly, the decrypted string must be converted to utf8 before the lower will work with it properly. Yay SQL.
    if Filter.has_key("forename"):
        if where == False:
            query += " WHERE "
            where = True
        else:
            query += " AND "
        if like:
            query += "LOWER(CONVERT(AES_DECRYPT(Forename,'{AES}') USING 'utf8')) LIKE '%{forename}%'".format(**{"forename":sql_sanitise(Filter["forename"]),"AES":sql_sanitise(aes_key)})
        else:
            query += "LOWER(CONVERT(AES_DECRYPT(Forename,'{AES}') USING 'utf8')) = '{forename}'".format(**{"forename":sql_sanitise(Filter["forename"]),"AES":sql_sanitise(aes_key)})
    if Filter.has_key("surname"):
        if where == False:
            query += " WHERE "
            where = True
        else:
            query += " AND "
        if like:
            query += "LOWER(CONVERT(AES_DECRYPT(Surname,'{AES}') USING 'utf8')) LIKE '%{surname}%'".format(**{"surname":sql_sanitise(Filter["surname"]),"AES":sql_sanitise(aes_key)})
        else:
            query += "LOWER(CONVERT(AES_DECRYPT(Surname,'{AES}') USING 'utf8')) = '{surname}'".format(**{"surname":sql_sanitise(Filter["surname"]),"AES":sql_sanitise(aes_key)})

    # Connect to the database and run the query
    db = connect_db()
    cur = db.cursor()
    cur.execute(query)
    data = list(cur.fetchall())
    cur.close()
    for row in range(len(data)):
        data[row] = {"Username":data[row][0],"Forename":data[row][1],"Surname":data[row][2]}
    db.close()

    return json.dumps({"status":"OK","data":data})

@api.route("add_new_incident",["POST"])
def add_new_incident(request):
    user = get_username(request)
    if get_rank(user) > 2: # If not a prefect
        raise RankError
    if not (request.form.has_key("user")):
        return json.dumps({"status":"BAD","error":"Missing username."})
    else:
        student = sql_sanitise(str(request.form["user"].lower()),underscore=False,percent=False)
    if not (request.form.has_key("report")):
        return json.dumps({"status":"BAD","error":"Missing report."})
    else:
        report = sql_sanitise(str(request.form["report"]))
    if not (request.form.has_key("date")):
        date = datetime.date.today().strftime("%Y-%m-%d")
    else:
        date = sql_sanitise(str(request.form["date"]))

    # Get the private key
    key = get_private_key(request)

    # Get the AES key for the database
    aes_key = sql_sanitise(get_file_key(user,key))

    # Set up the query
    query = "INSERT INTO Incidents(Username, Report, Date) VALUES "+\
            "(AES_ENCRYPT('{username}','{AES}'),AES_ENCRYPT('{report}','{AES}'),'{date}');".format(**{"AES":aes_key,"username":student,"report":report,"date":date})

    # Connect and run the query
    db = connect_db()
    cur = db.cursor()
    try:
        cur.execute(query)
    except MySQLdb.IntegrityError:
        raise ForeignKeyError
    db.commit()
    cur.close()
    db.close()

    return json.dumps({"status":"OK"})

@api.route("query_incident")
def incident_query(request):
    user = get_username(request)

    Filter = {}
    try:
        if request.args.has_key("user"):
            Filter["user"] = str(request.args["user"]).lower()
        if request.args.has_key("before"):
            Filter["before"] = str(request.args["before"])
        if request.args.has_key("after"):
            Filter["after"] = str(request.args["after"])
        if request.args.has_key("id"):
            Filter["id"] = str(request.args["id"]).split(" ")
    except:
        return json.dumps({"status":"BAD","error":"Invalid arguments."})
    

    # Get the user's private key
    key = get_private_key(request)

    # Get the database AES key
    aes_key = get_file_key(user,key)

    # Generate the query based on whether there is a filter or not
    query = "SELECT IncidentID,AES_DECRYPT(Username,'{AES}'),AES_DECRYPT(Report,'{AES}'),Date FROM Incidents".format(**{"AES":sql_sanitise(aes_key)})

    where = False
    
    if Filter.has_key("user"):
        if where == False:
            query += " WHERE "
            where = True
        else:
            query += " AND "
        query += "AES_DECRYPT(Username,'{AES}') = '{user}'".format(**{"user":sql_sanitise(Filter["user"],underscore=False,percent=False),"AES":sql_sanitise(aes_key)})
    # Weirdly, the decrypted string must be converted to utf8 before the lower will work with it properly. Yay SQL.
    if Filter.has_key("before"):
        if where == False:
            query += " WHERE "
            where = True
        else:
            query += " AND "
        query += "Date < '{date}'".format(**{"date":sql_sanitise(Filter["before"])})
    if Filter.has_key("after"):
        if where == False:
            query += " WHERE "
            where = True
        else:
            query += " AND "
        query += "Date > '{date}'".format(**{"date":sql_sanitise(Filter["after"])})
    if Filter.has_key("id"):
        if where == False:
            query += " WHERE "
            where = True
        else:
            query += " AND "
        query+="("
        OR = False
        for ID in Filter["id"]:
            if OR:
                query += " OR "
            else:
                OR = True
            
            query += "IncidentID = {id}".format(**{"id":ID})
        query+=")"

    # Connect to the database and run the query
    db = connect_db()
    cur = db.cursor()
    cur.execute(query)
    data = list(cur.fetchall())
    for row in range(len(data)):
        data[row] = {"ID":data[row][0],"Username":data[row][1],"Report":data[row][2],"Date":data[row][3].strftime("%Y-%m-%d")}
    cur.close()
    db.close()

    return json.dumps({"status":"OK","data":data})

@api.route("add_new_sanction",["POST"])
def add_new_sanction(request):
    user = get_username(request)
    if get_rank(user) > 1: # If not a teacher
        raise RankError
    if not (request.form.has_key("id")):
        return json.dumps({"status":"BAD","error":"Missing incident ID."})
    else:
        incident = int(request.form["id"])
    if not (request.form.has_key("sanction")):
        return json.dumps({"status":"BAD","error":"Missing sanction."})
    else:
        sanction = sql_sanitise(str(request.form["sanction"]))
    if not (request.form.has_key("start_date")):
        start_date = datetime.date.today().strftime("%Y-%m-%d")
    else:
        start_date = sql_sanitise(str(request.form["start_date"]))
    if not (request.form.has_key("end_date")):
        return json.dumps({"status":"BAD","error":"Missing end date."})
    else:
        end_date = sql_sanitise(str(request.form["end_date"]))

    # Get the private key
    key = get_private_key(request)

    # Get the AES key for the database
    aes_key = sql_sanitise(get_file_key(user,key))

    # Set up the query
    query = "INSERT INTO Sanctions(IncidentID, StartDate, EndDate, Sanction) VALUES "+\
            "({id},'{start_date}','{end_date}',AES_ENCRYPT('{sanction}','{AES}'));".format(**{"AES":aes_key,"id":incident,"sanction":sanction,"start_date":start_date,"end_date":end_date})
    
    # Connect and run the query
    db = connect_db()
    cur = db.cursor()
    try:
        cur.execute(query)
    except MySQLdb.IntegrityError:
        raise ForeignKeyError
    db.commit()
    cur.close()
    db.close()

    return json.dumps({"status":"OK"})

@api.route("query_sanction")
def sanction_query(request):
    user = get_username(request)

    Filter = {}
    try:
        if request.args.has_key("incident"):
            Filter["incident"] = [int(i) for i in str(request.args["incident"]).split(" ")]
        if request.args.has_key("starts_before"):
            Filter["starts_before"] = str(request.args["starts_before"])
        if request.args.has_key("starts_after"):
            Filter["starts_after"] = str(request.args["starts_after"])
        if request.args.has_key("ends_before"):
            Filter["ends_before"] = str(request.args["ends_before"])
        if request.args.has_key("ends_after"):
            Filter["ends_after"] = str(request.args["ends_after"])
        if request.args.has_key("id"):
            Filter["id"] = [int(i) for i in str(request.args["id"]).split(" ")]
    except:
        return json.dumps({"status":"BAD","error":"Invalid arguments."})
    

    # Get the user's private key
    key = get_private_key(request)

    # Get the database AES key
    aes_key = get_file_key(user,key)

    # Generate the query based on whether there is a filter or not
    query = "SELECT SanctionID,StartDate,EndDate,AES_DECRYPT(Sanction,'{AES}'),IncidentID FROM Sanctions".format(**{"AES":sql_sanitise(aes_key)})

    where = False
    
    if Filter.has_key("incident"):
        if where == False:
            query += " WHERE "
            where = True
        else:
            query += " AND "
        query += "("
        OR = False
        for incident in Filter["incident"]:
            if OR:
                query += " OR "
            else:
                OR = True
            query += "IncidentID = {incident}".format(**{"incident":incident})
        query += ")"
    # Weirdly, the decrypted string must be converted to utf8 before the lower will work with it properly. Yay SQL.
    if Filter.has_key("starts_before"):
        if where == False:
            query += " WHERE "
            where = True
        else:
            query += " AND "
        query += "StartDate < '{date}'".format(**{"date":sql_sanitise(Filter["starts_before"])})
    if Filter.has_key("starts_after"):
        if where == False:
            query += " WHERE "
            where = True
        else:
            query += " AND "
        query += "StartDate > '{date}'".format(**{"date":sql_sanitise(Filter["starts_after"])})
    if Filter.has_key("ends_before"):
        if where == False:
            query += " WHERE "
            where = True
        else:
            query += " AND "
        query += "EndDate < '{date}'".format(**{"date":sql_sanitise(Filter["ends_before"])})
    if Filter.has_key("ends_after"):
        if where == False:
            query += " WHERE "
            where = True
        else:
            query += " AND "
        query += "EndDate > '{date}'".format(**{"date":sql_sanitise(Filter["ends_after"])})
    
    if Filter.has_key("id"):
        if where == False:
            query += " WHERE "
            where = True
        else:
            query += " AND "
        query+="("
        OR = False
        for ID in Filter["id"]:
            if OR:
                query += " OR "
            else:
                OR = True
            query += "SanctionID = {id}".format(**{"id":ID})
        query+=")"

    # Connect to the database and run the query
    db = connect_db()
    cur = db.cursor()
    cur.execute(query)
    data = list(cur.fetchall())
    for row in range(len(data)):
        data[row] = {"ID":data[row][0],"StartDate":data[row][1].strftime("%Y-%m-%d"),"EndDate":data[row][2].strftime("%Y-%m-%d"),"Sanction":data[row][3],"IncidentID":data[row][4]}
    cur.close()
    db.close()

    return json.dumps({"status":"OK","data":data})

@api.route("modify_student",["POST"])
def modify_user(request):
    user = get_username(request)
    if get_rank(user) > 2: # If not a prefect
        raise RankError

    if not (request.form.has_key("user")):
        return json.dumps({"status":"BAD","error":"Missing username."})
    else:
        student = sql_sanitise(str(request.form["user"]),underscore=False,percent=False).lower()
    if not (request.form.has_key("delete_photo")):
        delete_photo = False
    else:
        delete_photo = bool(request.form["delete_photo"])
    if not (request.form.has_key("delete")):
        delete = False
    else:
        delete = bool(request.form["delete"])
        delete_photo = bool(request.form["delete"])
    if not (request.form.has_key("new_user")):
        new = None
    else:
        new = sql_sanitise(str(request.form["new_user"]),underscore=False,percent=False).lower()
    if not (request.form.has_key("forename")):
        forename = None
    else:
        forename = sql_sanitise(str(request.form["forename"]))
    if not (request.form.has_key("surname")):
        surname = None
    else:
        surname = sql_sanitise(str(request.form["surname"]))
    if request.files.has_key("photo"):
        photo = request.files["photo"]
    else:
        photo = None

    # Get the user's private key
    key = get_private_key(request)

    # Get the database AES key
    aes_key = sql_sanitise(get_file_key(user,key))

    # Handle a request to delete by deleting the selected user
    # I would have used HTTP DELETE requests for this, however the user to delete is specified in form data, which is not supposed to be used with DELETE.
    # DELETE is more designed for proper URLs, anyway.
    # I could get around this by doing something such as /delete_student/<username> but this would be fairly inconsistent with the way the API has been designed in the first place.
    # Besides, DELETE is supported in *HTTP* but not very well supported in HTML.
    if delete:
        # First we need to get any incidents that are connected to them.
        db = connect_db()
        cur = db.cursor()
        cur.execute("SELECT IncidentID FROM Incidents WHERE AES_DECRYPT(Username,'{AES}') = '{user}';".format(**{"AES":aes_key,"user":student}))
        incidents = [str(i[0]) for i in cur.fetchall()]
        if len(incidents) > 0:
            # Now we delete any connected sanctions
            condition = "' OR IncidentID = '".join(incidents)
            query = "DELETE FROM Sanctions WHERE IncidentID = '"+condition+"';"
            cur.execute(query)
            
            # And then the incidents themselves
            query = "DELETE FROM Incidents WHERE IncidentID = '"+condition+"';"
            if not cur.execute(query) == len(incidents):
                return json.dumps({"status":"BAD","error":"Internal error: number of incidents deleted different from number found. Changes have not been committed."})

        # Now we can delete the user data
        cur.execute("DELETE FROM Students WHERE AES_DECRYPT(Username,'{AES}') = '{user}';".format(**{"AES":aes_key,"user":student}))
        db.commit()
        cur.close()
        db.close()
        return json.dumps({"status":"OK","data":"User '{user}' deleted.".format(**{"user":student})})
    # Otherwise, this is a modify request, so use UPDATE
    else:
        columns = []
        if new:
            columns.append("Username = AES_ENCRYPT('{new}','{AES}')".format(**{"new":new,"AES":aes_key}))
        if forename:
            columns.append("Forename = AES_ENCRYPT('{forename}','{AES}')".format(**{"forename":forename,"AES":aes_key}))
        if surname:
            columns.append("Surname = AES_ENCRYPT('{surname}','{AES}')".format(**{"surname":surname,"AES":aes_key}))
        if len(columns) > 0:
            query = "UPDATE Students SET "+", ".join(columns)+" WHERE AES_DECRYPT(Username,'{AES}') = '{user}'".format(**{"user":student,"AES":aes_key})
            db = connect_db()
            cur = db.cursor()
            cur.execute(query)
            db.commit()
            cur.close()
            db.close()

        if photo or delete_photo:
            db = connect_db()
            cur = db.cursor()
            photoID = get_photoID(student,aes_key,cur)
            
    
            if photo != None:
                filekey = upload_file(photo,photoID,db,cur)
                if not filekey:
                    return json.dumps({"status":"OK","error":"Failed to upload photo."})
                else:
                    # We need to encrypt this key and give every user access to it
                    add_new_filekey(photoID,filekey,db,cur)
            
            if delete_photo:
                delete_file(photoID,db,cur)
                
            cur.close()
            db.close()
        return json.dumps({"status":"OK"})

@api.route("modify_incident",["POST"])
def modify_incident(request):
    user = get_username(request)
    if get_rank(user) > 2: # If not a prefect
        raise RankError

    if not (request.form.has_key("id")):
        return json.dumps({"status":"BAD","error":"Missing ID."})
    else:
        incident = int(request.form["id"])
    if not (request.form.has_key("delete")):
        delete = False
    else:
        delete = bool(request.form["delete"])
    if not (request.form.has_key("new_user")):
        new = None
    else:
        new = sql_sanitise(str(request.form["new_user"])).lower()
    if not (request.form.has_key("report")):
        report = None
    else:
        report = sql_sanitise(str(request.form["report"]))
    if not (request.form.has_key("date")):
        date = None
    else:
        date = sql_sanitise(str(request.form["date"]))

    # Get the user's private key
    key = get_private_key(request)

    # Get the database AES key
    aes_key = sql_sanitise(get_file_key(user,key))

    if delete:
        # First we need to delete any sanctions.
        db = connect_db()
        cur = db.cursor()
        query = "DELETE FROM Sanctions WHERE IncidentID = {id};".format(**{"id":incident})
        cur.execute(query)
        # Now we can delete the incident.
        cur.execute("DELETE FROM Incidents WHERE IncidentID = {id};".format(**{"id":incident}))
        db.commit()
        cur.close()
        db.close()
        return json.dumps({"status":"OK","data":"Incident {id} deleted.".format(**{"id":incident})})
    # Otherwise, this is a modify request, so use UPDATE
    else:
        columns = []
        if new:
            columns.append("Username = AES_ENCRYPT('{new}','{AES}')".format(**{"new":new,"AES":aes_key}))
        if report:
            columns.append("Report = AES_ENCRYPT('{report}','{AES}')".format(**{"report":report,"AES":aes_key}))
        if date:
            columns.append("Date = '{date}'".format(**{"date":date}))
        if len(columns) > 0:
            query = "UPDATE Incidents SET "+", ".join(columns)+" WHERE IncidentID = {id}".format(**{"id":incident})
        else:
            return json.dumps({"status":"OK"})
        db = connect_db()
        cur = db.cursor()
        cur.execute(query)
        db.commit()
        cur.close()
        db.close()
        return json.dumps({"status":"OK"})

@api.route("modify_sanction",["POST"])
def modify_sanction(request):
    user = get_username(request)
    if get_rank(user) > 1: # If not a teacher
        raise RankError

    if not (request.form.has_key("id")):
        return json.dumps({"status":"BAD","error":"Missing ID."})
    else:
        ID = int(request.form["id"])
    if not (request.form.has_key("delete")):
        delete = False
    else:
        delete = bool(request.form["delete"])
    if not (request.form.has_key("new_incident")):
        new = None
    else:
        new = int(request.form["new_incident"])
    if not (request.form.has_key("sanction")):
        sanction = None
    else:
        sanction = sql_sanitise(str(request.form["sanction"]))
    if not (request.form.has_key("start_date")):
        start_date = None
    else:
        start_date = sql_sanitise(str(request.form["start_date"]))
    if not (request.form.has_key("end_date")):
        end_date = None
    else:
        end_date = sql_sanitise(str(request.form["end_date"]))

    # Get the user's private key
    key = get_private_key(request)

    # Get the database AES key
    aes_key = sql_sanitise(get_file_key(user,key))

    if delete:
        # First we need to delete any sanctions.
        db = connect_db()
        cur = db.cursor()
        query = "DELETE FROM Sanctions WHERE SanctionID = {id};".format(**{"id":ID})
        cur.execute(query)
        db.commit()
        cur.close()
        db.close()
        return json.dumps({"status":"OK","data":"Sanction {id} deleted.".format(**{"id":ID})})
    # Otherwise, this is a modify request, so use UPDATE
    else:
        columns = []
        if new:
            columns.append("IncidentID = {new}".format(**{"new":new}))
        if sanction:
            columns.append("Sanction = AES_ENCRYPT('{sanction}','{AES}')".format(**{"sanction":sanction,"AES":aes_key}))
        if start_date:
            columns.append("StartDate = '{start_date}'".format(**{"start_date":start_date}))
        if end_date:
            columns.append("EndDate = '{end_date}'".format(**{"end_date":end_date}))
        if len(columns) > 0:
            query = "UPDATE Sanctions SET "+", ".join(columns)+" WHERE SanctionID = {id}".format(**{"id":ID})
        else:
            return json.dumps({"status":"OK"})
        db = connect_db()
        cur = db.cursor()
        cur.execute(query)
        db.commit()
        cur.close()
        db.close()
        return json.dumps({"status":"OK"})

# Now we need a password change routine.
# This can be done by:
# 1) loading the user's private key
# 2) changing the password hash
# 3) generating the new AES key and re-encrypting the private key
# The user must be logged in already, but they must also provide their current password
@api.route("change_password",["POST"])
def change_password(request):
    user = get_username(request)

    if not (request.form.has_key("pass")):
        return json.dumps({"status":"BAD","error":"Missing current password."})
    else:
        passwd = str(request.form["pass"])
    if not (request.form.has_key("new")):
        return json.dumps({"status":"BAD","error":"Missing new password."})
    else:
        new = str(request.form["new"])

    # Validate that the old password is correct.
    db = connect_db()
    cur = db.cursor()
    if cur.execute("SELECT PasswordHash,Salt FROM Accounts WHERE Login = '{user}';".format(**{"user":sql_sanitise(user)})) != 1:
        return json.dumps({"status":"BAD","error":"Incorrect username/password."})
    pwhash,salt = cur.fetchall()[0]
    hasher = SHA256.new()
    hasher.update(salt+passwd)
    if pwhash != hasher.digest():
        return json.dumps({"status":"BAD","error":"Incorrect username/password."})

    # Old password is correct, generate the new password hash
    salt = os.urandom(8)
    hasher = SHA256.new()
    hasher.update(salt+new)
    pwhash = hasher.digest()

    # Make the AES key
    hasher = SHA256.new()
    hasher.update(new)
    h = hasher.digest()
    hasher = SHA256.new()
    hasher.update(user+new+h)
    aes_key = hasher.digest()

    # Load and export the private key
    key = get_private_key(request)
    exported = key.exportKey()

    # Connect to the database, add the new hash, and re-encrypt the private key
    db = connect_db()
    cur = db.cursor()
    cur.execute("UPDATE Accounts SET PasswordHash = UNHEX('{hash}'), Salt = UNHEX('{salt}'), PrivateKey = AES_ENCRYPT('{RSA}','{AES}') WHERE Login = '{user}';".format(**{"AES":sql_sanitise(aes_key),"hash":pwhash.encode("hex"),"salt":salt.encode("hex"),"RSA":sql_sanitise(exported),"user":user}))
    db.commit()
    cur.close()
    db.close()

    # Now we need to delete the API key and make the user log in again
    # We do this by blanking the cookies and setting them to expire immediately
    return logout(app)

# Now we need to be able to create new users
# New users need a Login name and password (which will create their encryption key)
# They will also need an RSA key generated for them
# Thankfully, we have a function in place already for creating a new user
# However, after we add a new user, we will have to give them access to the database
# This means that the admin will have to decrypt all of their own keys and give them to the new user
# With this, we will begin to add features of account ranks, as only admins should be able to create new users
# 0 = admin
# 1 = teacher
# 2 = student
# Admins can access all functions
# Teachers can access all except managing other user accounts
# Students can only submit incidents and make queries

@api.route("add_new_account",["POST"])
def create_account(request):
    if not (request.form.has_key("user")):
        return json.dumps({"status":"BAD","error":"Missing username."})
    else:
        username = str(request.form["user"])
    if not (request.form.has_key("pass")):
        return json.dumps({"status":"BAD","error":"Missing password."})
    else:
        passwd = str(request.form["pass"])
    if not (request.form.has_key("rank")):
        return json.dumps({"status":"BAD","error":"Missing rank."})
    else:
        rank = int(request.form["rank"])
        
    user = get_username(request)
    if get_rank(user) > 0: # If not an admin
        raise RankError
    # If we can get the admin's private key, they are logged in
    # Besides this, we will need the key later
    key = get_private_key(request)

    # Use the add_new_account function to insert a new account into the database
    db = connect_db()
    new_key = add_new_account(username,passwd,rank,db)

    # Now we need to get the FileKeys for the current user
    db = connect_db()
    cur = db.cursor()
    cur.execute("SELECT FileID FROM FileKeys WHERE Login = '{user}';".format(**{"user":sql_sanitise(user)}))
    keys = [{"id":k[0]} for k in cur.fetchall()]
    cur.close()
    db.close()

    # And re-encrypt all of the keys
    for k in range(len(keys)):
        aes_key = get_file_key(user,key,keys[k]["id"]).encode("hex")
        e_aes_key = new_key.encrypt(aes_key,0)[0]
        keys[k]["new_key"] = e_aes_key.encode("hex")

    # Now we insert all the new keys into the database
    db = connect_db()
    cur = db.cursor()
    for k in range(len(keys)):
        query = "INSERT INTO FileKeys VALUES ('{username}','{file_id}',UNHEX('{key}'));".format(**{"username":sql_sanitise(username),"file_id":sql_sanitise(keys[k]["id"]),"key":sql_sanitise(keys[k]["new_key"])})
        cur.execute(query)
    db.commit()
    cur.close()
    db.close()
    return json.dumps({"status":"OK"})

# We may want to delete old accounts
@api.route("delete_account",["POST"])
def delete_account(request):
    user = get_username(request)
    rank = get_rank(user)
    # Get the user's private key -- this verifies they are logged in
    if not (request.form.has_key("user")):
        username = user
    else:
        username = request.form["user"]
    if (username == user and bool(int(configman.read("config/defaults.cnf")["USERS_CAN_DELETE_THEMSELVES"]))) or rank == 0: # This allows admins to do this for other users
        username = str(request.form["user"])
    else:
        raise RankError
    if (request.form.has_key("pass")):
        passwd = request.form["pass"]
    else:
        passwd = None
    
    db = connect_db()
    cur = db.cursor()
    # If the user is an admin, we need to be sure they're not the only remaining admin
    if get_rank(username) == 0:
        if cur.execute("SELECT * FROM Accounts WHERE AccountType = 0;") <= 1:
            return json.dumps({"status":"BAD","error":"Can't delete only remaining administrator account."})
    # If the user is deleting their own account, they should require their password
    if username == user:
        if passwd == None:
            return json.dumps({"status":"BAD","error":"Missing password."})
        cur.execute("SELECT PasswordHash,Salt FROM Accounts WHERE Login = '{user}';".format(**{"user":sql_sanitise(username)}))
        server_h,salt = cur.fetchall()[0]
        hasher = SHA256.new()
        # For some reason, this produces a UnicodeDecodeError. Concatenating the hex-encoded versions and then un-hexing it solved this problem.
        to_hash = (salt.encode("hex")+passwd.encode("hex")).decode("hex")
        hasher.update(to_hash)
        h = hasher.digest()
        passwd = None
        if h != server_h:
            raise AuthenticationError
    # Now we can actually delete the account
    cur.execute("DELETE FROM FileKeys WHERE Login = '{user}';".format(**{"user":sql_sanitise(username)}))
    cur.execute("DELETE FROM Accounts WHERE Login = '{user}';".format(**{"user":sql_sanitise(username)}))
    db.commit()
    cur.close()
    db.close()
    # Log the user out if they deleted their own account
    if user == username:
        return logout(app)
    return json.dumps({"status":"OK"})

# Since we can upload photos, we want to be able get a user's photo
@api.route("photo",["GET"])
def get_photo(request):
    if not (request.args.has_key("user")):
        return json.dumps({"status":"BAD","error":"Missing username!"})
    else:
        student = request.args["user"]
        
    user = get_username(request)
    
    # Get the user's private key
    key = get_private_key(request)

    # Get the database AES key
    aes_key = sql_sanitise(get_file_key(user,key))

    # Get the student's photoID
    db = connect_db()
    cur = db.cursor()
    photoID = get_photoID(sql_sanitise(student,underscore=False,percent=False),aes_key,cur)
    cur.close()
    db.close()

    # Get the photo's filekey
    try:
        photokey = get_file_key(user,key,str(photoID))
    except FileKeyError:
        raise PhotoError

    # And decrypt the image, to a StringIO
    path = configman.read("config/defaults.cnf")["PHOTO_FOLDER"]
    path += "/"+str(photoID)+".jpg"
    im = decrypt_image(photokey,path,stringio=True)

    return send_file(im,mimetype="image/jpeg")

@api.route("logout",["POST"])
def log_user_out(request):
    return logout(app)
    
api.start("/api/v1")


# Now we'll start a client object so we can register webpages to be hosted by the Flask server
# While we could just register them normally (e.g. @app.route), this method will allow automatic error handling
client = apiframework.Client(app)

client.add_route("index.html","client/index.html")
client.add_route(["banman.ico","incidents/banman.ico"],"client/favicon.ico")
client.add_route(["makeasync.js","incidents/makeasync.js"],"client/makeasync.js")
client.add_route(["banman.js","incidents/banman.js"],"client/banman.js")
client.add_route(["menubar.js","incidents/menubar.js"],"client/menubar.js")
client.add_route(["default.css","incidents/default.css"],"client/default.css")
client.add_route("setup","client/setup.html")
client.add_route("ajax-loader.gif","client/ajax-loader.gif")
client.add_route("login","client/login.html")
client.add_route("dash","client/dashboard.html")
client.add_route("logout","client/logout.html")
client.add_route("incidents","client/incidents.html")
client.add_route("incidents/view_incident","client/view_incident.html")
client.add_route("incidents/add_incident","client/new_incident.html")

client.start()
