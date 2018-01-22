##API for a prefect ban management system

import apiframework
import MySQLdb
import os
import json
import configman

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
                        "Report MEDIUMTEXT,"+\
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
    except Exception,e:
        return json.dumps({"status":"BAD","error":"Failed to set up database!","data":str(e)})

    try:
        configman.write("config/SQLusers.cnf",
                        {"initialised":"1","admin":user,"host":hostname})
    except Exception,e:
        return json.dumps({"status":"BAD","error":"Failed to write config!","data":str(e)})
    return json.dumps({"status":"OK","data":"Initialised"})

api.start()
