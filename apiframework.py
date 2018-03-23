##API Webserver

# This is going to be a framework for building up the API, rather than the API
# itself. My reasoning for this is that it allows a future developer to expand
# the functions of the API without needing to go too deeply into the grisly
# details of the backend.

# It will be based on code from a previous project with the same goals in mind.

from flask import Flask,request,Response,send_from_directory
from flask_cors import CORS
import configman
from configman import ConfigError
from specialexceptions import *
import os
import json

##app = Flask(__name__)
##CORS(app)

class API(object):
    def __init__(self,app):
        self.app = app
        self.functions = {} # define an empty dictionary.
        # Requests received will be looked up in this dictionary to find the
        # appropriate function

    def start(self,route="/api"):
        # The base Flask route is set up. All requests will come through this route.
        # The start of the URL is the base route. This is defined when calling this function
        # Next is the function requested
        # Function arguments will be given in the request
        @self.app.route(route+"/<f>",methods=["GET","POST","PUT","DELETE"])
        def api_main(f):
            if not self.functions.has_key(f):
                return Response(status=404) # 404 if function does not exist
            else:
                try:
                    if request.method in self.functions[f][1]:
                        # We want to remove any "dud" arguments
                        request.args = dict([i for i in request.args.items() if (i[0] != "") and (i[1] != "")])
                        request.form = dict([i for i in request.form.items() if (i[0] != "") and (i[1] != "")])
                        
                        if self.functions[f][0].func_code.co_argcount == 1:
                            return self.functions[f][0](request)
                        elif self.functions[f][0].func_code.co_argcount == 0:
                            return self.functions[f][0]()
                        else:
                            return Response(status=405)
                    else:
                        return Response(status=405)
                    # The request is passed to the function, allowing it to extract information from the HTTP request

                except AuthenticationError:
                    return json.dumps({"status":"BAD","error":"Invalid authentication cookie. Please login again."})
                except ConfigError:
                    return json.dumps({"status":"BAD","error":"Failed to load/write config."})
                except FileKeyError:
                    return json.dumps({"status":"BAD","error":"No access to file."})
                except DatabaseConnectError:
                    return json.dumps({"status":"BAD","error":"Failed to connecct to database."})
                except RecordExistsError:
                    return json.dumps({"status":"BAD","error":"Record already exists!"})
                except ForeignKeyError:
                    return json.dumps({"status":"BAD","error":"Related record does not exist."})
                except RankError:
                    return json.dumps({"status":"BAD","error":"User not a high enough rank to perform that operation."})
                except PhotoError:
                    return send_from_directory(self.app.root_path,"user.jpg",
                                               mimetype="image/jpeg")
                except InvalidInputError:
                    return json.dumps({"status":"BAD","error":"There are invalid characters in your input. Please try again."})
                except InvalidDateError:
                    return json.dumps({"status":"BAD","error":"The end date is before the start date."})

    # Function decorator for defining an API route. The route name is the f passed to the main route.
    def route(self,name,methods=["GET"]):
        def decorator(function):
            def wrapper():
                return function
            self.functions[name] = (function,methods)
            return wrapper()
        return decorator
            
class Client(object):
    def __init__(self,app):
        self.app = app
        self.routes = {}

    def start(self,route=""):
        # This sets up a route that requires a page argument to load
        # This shouldn't conflict with the api route
        # We register pages to this route which are served by Flask
        # Rather than using templates, I have opted for sending files
        # By this method, we lose the ability to fill-in the page with data from the flask server, but makes it very easy to host images, js, css, etc. on the flask server
        # Thankfully, we don't need templates, since the pages will all interface with the api!
        @self.app.route(route+"/<path:page>",methods=["GET","POST","PUT","DELETE"])
        def client_main(page):
            if not self.routes.has_key(page):
                return Response(status=404) # 404 if page does not exist
            else:
                return send_from_directory(self.routes[page][0],
                                           self.routes[page][1])

        # We have to handle the index page separately from everything else
        @self.app.route("/",methods=["GET","POST","PUT","DELETE"])
        def index_page():
            if not self.routes.has_key("/"):
                return Response(status=404) # 404 if page does not exist
            else:
                return send_from_directory(self.routes["/"][0],
                                           self.routes["/"][1])
                    
    def add_route(self,name,page):
        data = (os.path.dirname(page),os.path.basename(page))
        if isinstance(name,str):
            if os.path.basename(name)[:6] == "index.": # This allows our index pages to be registered to the / as well as the /<name> -- something we must do manually in Flask
                self.routes[os.path.dirname(name)+"/"] = data
            self.routes[name] = data
        elif isinstance(name,list):
            for n in name:
                if os.path.basename(n)[:6] == "index.": # This allows our index pages to be registered to the / as well as the /<name> -- something we must do manually in Flask
                    self.routes[os.path.dirname(n)+"/"] = data
                self.routes[n] = data
        else:
            raise TypeError
