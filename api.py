##API for a prefect ban management system

import apiframework
from apiframework import AuthenticationError, ConfigError, ForeignKeyError, RecordExistsError
from useful_functions import *
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

app = apiframework.app
api = apiframework.API()

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
                    "Sanction BLOB,"+\
                    "IncidentID INTEGER,"+\
                    "FOREIGN KEY (IncidentID) REFERENCES Incidents(IncidentID));")
        db.commit()

        cur.execute("CREATE TABLE Accounts "+\
                    "(Login VARCHAR({max_login_length}) PRIMARY KEY NOT NULL,".format(**{"max_login_length":MAX_LOGIN_LENGTH})+\
                    "PasswordHash BINARY(32) NOT NULL,"+\
                    "PublicKey TEXT NOT NULL,"+\
                    "PrivateKey BLOB NOT NULL,"+\
                    "AccountType INTEGER NOT NULL,"+\
                    "Email VARBINARY(256));")
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

# This function is for adding a new student to the database.
# The student's username is required, but their forename and surname are optional
@api.route("add_new_student",["POST"])
def add_new_student(request):
    #sql_cfg = get_SQL_config()
    user = get_username(request)
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

    db = connect_db()
    cur = db.cursor()
    try:
        cur.execute(query)
    except MySQLdb.IntegrityError:
        raise RecordExistsError
    db.commit()
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
            Filter["user"] = str(request.args["user"]).lower()
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
        if like:
            query += "AES_DECRYPT(Username,'{AES}') LIKE '%{user}%'".format(**{"user":sql_sanitise(Filter["user"]),"AES":sql_sanitise(aes_key)})
        else:
            query += "AES_DECRYPT(Username,'{AES}') = '{user}'".format(**{"user":sql_sanitise(Filter["user"]),"AES":sql_sanitise(aes_key)})
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
    if not (request.form.has_key("user")):
        return json.dumps({"status":"BAD","error":"Missing username."})
    else:
        student = sql_sanitise(str(request.form["user"].lower()))
    if not (request.form.has_key("report")):
        return json.dumps({"status":"BAD","error":"Missing username."})
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
            Filter["id"] = str(request.args["id"])
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
        query += "AES_DECRYPT(Username,'{AES}') = '{user}'".format(**{"user":sql_sanitise(Filter["user"]),"AES":sql_sanitise(aes_key)})
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
        query += "IncidentID = {id}".format(**{"id":Filter["id"]})

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
            Filter["incident"] = int(request.args["incident"])
        if request.args.has_key("starts_before"):
            Filter["starts_before"] = str(request.args["starts_before"])
        if request.args.has_key("starts_after"):
            Filter["starts_after"] = str(request.args["starts_after"])
        if request.args.has_key("ends_before"):
            Filter["ends_before"] = str(request.args["ends_before"])
        if request.args.has_key("ends_after"):
            Filter["ends_after"] = str(request.args["ends_after"])
        if request.args.has_key("id"):
            Filter["id"] = str(request.args["id"])
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
        query += "IncidentID = {incident}".format(**{"incident":Filter["incident"]})
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
        query += "SanctionID = {id}".format(**{"id":Filter["id"]})

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

    if not (request.form.has_key("user")):
        return json.dumps({"status":"BAD","error":"Missing username."})
    else:
        student = sql_sanitise(str(request.form["user"])).lower()
    if not (request.form.has_key("delete")):
        delete = False
    else:
        delete = bool(request.form["delete"])
    if not (request.form.has_key("new_user")):
        new = None
    else:
        new = sql_sanitise(str(request.form["new_user"])).lower()
    if not (request.form.has_key("forename")):
        forename = None
    else:
        forename = sql_sanitise(str(request.form["forename"]))
    if not (request.form.has_key("surname")):
        surname = None
    else:
        surname = sql_sanitise(str(request.form["surname"]))

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
    
    
api.start()
