##API for a prefect ban management system

import apiframework
import MySQLdb
import os
import json
import configreader

app = apiframework.app
api = apiframework.API()

@api.route("status")
def status():
    data = {}
    if "SQLusers.cnf" not in os.listdir("config"):
        data["initialised"] = False
    return json.dumps({"status":"OK","data":data})

@api.route("init")
def initialise(request):
    defaults = configreader.read("config/defaults.cnf")
    MAX_USERNAME_CHARS = defaults["MAX_USERNAME_CHARS"]
    MAX_FORENAME_LENGTH = defaults["MAX_FORENAME_LENGTH"]
    MAX_SURNAME_LENGTH = defaults["MAX_SURNAME_LENGTH"]

    if not (request.form.has_key("user") and request.form.has_key("pass")):
        return json.dumps({"status":"BAD","error":"Missing username and/or password."})
    else:
        user = request.form["user"]
        passwd = request.form["pass"]
    if not (request.form.has_key("host")):
        hostname = "localhost"
    else:
        hostname = request.form["host"]

    # Log into the server and create the new database
    db = MySQLdb.connect(host=hostname,
                         user=user,
                         passwd=passwd)
    cur = db.cursor()
    cur.execute("CREATE DATABASE BanManager;")
    db.commit()

    # Log in, using the new database, and create the tables
    db = MySQLdb.connect(host=hostname,
                         user=user,
                         passwd=passwd)
    cur = db.cursor()
##    cur.execute("CREATE TABLE Students "+\
##                "(Username VARCHAR("+MAX_USERNAME_CHARS+") 

    config = open("config/SQLusers.cnf","w")
    config.write("admin = "+user+"\nhost = "+hostname+"\n")
    config.close()

api.start()
