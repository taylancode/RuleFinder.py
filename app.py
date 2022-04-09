from flask import Flask, render_template, request, redirect, url_for, session
from sqlmanager import SQL
from rulefinder import Rulefinder

# Local py file for secret key and other variables
import constants

# Flask definitions
app = Flask(__name__)
app.secret_key = constants.FLASK_KEY


# Column headings
headings = (
    "Rule Name",
    "Device Group",
    "Source Zone",
    "Dest Zone",
    "Source Address",
    "Source Users",
    "Dest Address",
    "Category",
    "Application",
    "Service",
    "Action",
    "Disabled"
    )

'''
Index route (main page)
GET request renders a search bar 
When POSTED, takes data from search bar and renders the data on the same page
'''

@app.route("/", methods=["POST", "GET"])
def index():

    if request.method == "POST":

        # Making an encrypted session
        ob = request.form["object"]
        session["object"] = ob

        # Get the Panorama address and key, required for object search
        fw = constants.FW
        key = constants.PA_KEY


        # Create instance of Rulefinder with params
        initfinder = Rulefinder(fw=fw, key=key, search_obj=session["object"])

        # Calls function to get objects from form data
        objects = initfinder.find_object()

        # Initiate the SQL manager
        initdb = SQL()

        # For the pages table data we append the data to rulelist[]
        rulelist = []

        # Find all rules for all objects in DB
        for object in objects:
            rule = initdb.excecute_sql(f"SELECT * FROM securityrules WHERE sourceip @> ARRAY['{object}'] or destip @> ARRAY['{object}']")
            rulelist.append(rule)

        # Close DB 
        initdb.close_connect(close_cur=True, close_DB=True, commit=False)

        # Render the data
        return render_template('objects.html',  rules=rulelist, headings=headings, objects=objects)
        
    else:
        return render_template('index.html')


'''
Simple redirect back to search page
When the navbar title is clicked it will redirect 
'''
@app.route("/home")
def home():
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run()