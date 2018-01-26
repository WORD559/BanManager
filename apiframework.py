##API Webserver

# This is going to be a framework for building up the API, rather than the API
# itself. My reasoning for this is that it allows a future developer to expand
# the functions of the API without needing to go too deeply into the grisly
# details of the backend.

# It will be based on code from a previous project with the same goals in mind.

from flask import Flask,request,Response,send_from_directory
import os

app = Flask(__name__)

class API(object):
    def __init__(self):
        self.functions = {} # define an empty dictionary.
        # Requests received will be looked up in this dictionary to find the
        # appropriate function
        self.favicon = None

    def start(self,route="/api"):
        # The base Flask route is set up. All requests will come through this route.
        # The start of the URL is the base route. This is defined when calling this function
        # Next is the function requested
        # Function arguments will be given in the request
        @app.route(route+"/<f>",methods=["GET","POST","PUT","DELETE"])
        def main(f):
            if not self.functions.has_key(f):
                return Response(status=404) # 404 if function does not exist
            else:
                try:
                    if request.method in self.functions[f][1]:
                        return self.functions[f][0](request) # Otherwise, return the output of the appropriate function
                    else:
                        return Response(status=405)
                    # The request is passed to the function, allowing it to extract information from the HTTP request
                except TypeError: # If the function takes no arguments
                    if request.method in self.functions[f][1]:
                        return self.functions[f][0]()
                    else:
                        return Response(status=405)

        @app.route("/favicon.ico")
        def return_favicon():
            if self.favicon != None:
                return send_from_directory(self.favicon[0],self.favicon[1],
                                           mimetype="image/vnd.microsoft.icon")
            else:
                return Response(status=404)

    # Function decorator for defining an API route. The route name is the f passed to the main route.
    def route(self,name,methods=["GET"]):
        def decorator(function):
            def wrapper():
                return function
            self.functions[name] = (function,methods)
            return wrapper()
        return decorator

    # Function for properly setting the favicon
    def set_favicon(self,path):
        if "/" not in path and "\\" not in path:
            self.favicon = (app.root_path,path)
        else:
            self.favicon = (os.path.dirname(path),os.path.basename(path))
            
