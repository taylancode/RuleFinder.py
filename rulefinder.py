import requests
import xml.etree.ElementTree as ET
import ipaddress
import socket
import re

# Importing the SQL manager from sqlmanager.py
from sqlmanager import SQL

# For ignoring certificate errors
requests.packages.urllib3.disable_warnings()

class Rulefinder(SQL):

    ENTRIES = [
        "from",
        "to",
        "source",
        "source-user",
        "destination",
        "category",
        "application",
        "service",
        "negate-source",
        "negate-destination",
        "action",
        "disabled"
    ]

    ENTRY_DICT = {
        "from": "fromzone",
        "to": "tozone",
        "source": "sourceip",
        "source-user": "sourceusr",
        "destination": "destip",
        "category": "category",
        "application": "application",
        "service": "service",
        "negate-source": "negatesrc",
        "negate-destination": "negatedest",
        "action": "action",
        "disabled": "disabled"
    }


    def __init__(self, fw=None, search_obj=None, key=None, dgrp=None):

        self.fw = fw
        self.search_obj = search_obj
        self.key = key
        self.dgrp = dgrp


        # Setting XPATHS
        self.rules = ("./result/security/rules/entry")
        self.objects = ("./result/address/entry")
        self.dest = ("./destination/member")
        self.src = ("./source/member")


        # Checking connection to panorama before attempting any API calls
        if self.check_con() is True:

            # To avoid extra API calls when not needed
            if dgrp is not None:


                self.getrules = requests.post(f"https://{self.fw}/api/?key={self.key}&type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{self.dgrp}']/post-rulebase/security", verify=False)
                
                if self.getrules.status_code == 200:
                        self.root = ET.fromstring(self.getrules.text)
                else:
                    raise Exception("Error: API call getrules failed, verify API key is correct.")

            # To avoid extra API calls when not needed
            if search_obj is not None:

                self.getobs = requests.post(f"https://{self.fw}/api/?key={self.key}&type=config&action=get&xpath=/config/shared/address", verify=False)

                if self.getobs.status_code == 200:
                    self.objectroot = ET.fromstring(self.getobs.text)
                else:
                    raise Exception("Error: API call getobs failed, verify API key is correct.")

        else:
            raise Exception("Error: Unable to connect to Panorama")


    def check_con(self) -> bool:

        '''
        Function to check connectivity to Panorama device
        All functionality relies on connection to Panorama
        Using the socket function we check for port 443 connectivity to Panorama for API calls
        Returns a boolean to be handled by other functions
        '''
        
        try:
            sock = socket.socket()
            sock.connect((self.fw, 443))
            return True
        
        except Exception:
            return False
        
        finally:
            sock.close()

    def check_obj(self) -> bool:

        '''
        Called via obj_converter()
        Checks if input is IP address or FQDN
        Returns True if it's an IP address and False if FQDN
        '''
        
        try:
            ipaddress.IPv4Network(self.search_obj)
            return True

        except ipaddress.AddressValueError:
            return False

    def obj_converter(self):

        '''
        Handles the user input of search_obj
        Calls check_obj() to check if input is IP address or FQDN
        DNS Queries to get the IP or FQDN
        We want to search all objects for IP and FQDN so we need both
        '''
        
        checkobj = self.check_obj()

        if checkobj == True:
            # Tries to get FQDN for IP, returns IP if no FQDN
            self.obj_fqdn = socket.getfqdn(self.search_obj)
            self.obj_ip = self.search_obj

        else:

            try:
                self.obj_ip = socket.gethostbyname(self.search_obj)

            # Handles exception if FQDN is irresolvable 
            except socket.gaierror:
                self.obj_ip = None

            finally:
                self.obj_fqdn = self.search_obj
        
    def find_object(self) -> dict:

        '''
        Function to check if IP or FQDN of search_obj exists in Panorama
        Calls Panorama and gets all objects in shared
        Iterates over all objects and checks if IP/FQDN matches search_obj
        If found, adds key/val pair to dictionary
        '''

        '''
        TODO: 
        Add optional check to find objects that cover the subnet
        Find associated object address groups
        Find associated URL categories 
        '''
    
        # Calling obj_converter to get both FQDN and IP
        self.obj_converter()

        # Make dictionary of objects found
        objects = {}

        # Iterate over objects
        for obs in self.objectroot.findall(self.objects):

            try:
                ip = obs.find("ip-netmask").text

                if ip == self.obj_ip:
                    
                    object_name = obs.get('name')
                    objects[object_name] = self.obj_ip

                # This is to cover the IPs that are specified with a /32 netmask
                elif ip == (f"{self.obj_ip}/32"):

                    object_name = obs.get('name')
                    objects[object_name] = (f"{self.obj_ip}/32")

            # Returns attribute error if "ip-netmask" doesn't exist 
            # which means it's an fqdn or other object so we ignore the error
            except AttributeError:
                pass

            try:
                fqdn = obs.find("fqdn").text

                # Ignoring case since objects are varied
                if re.search(f'{fqdn}', f'{self.obj_fqdn}', re.IGNORECASE):
                    object_name = obs.get('name')
                    objects[object_name] = self.obj_fqdn

            # Ignoring for same reasoning above
            except AttributeError:
                pass
        
        return objects


    def update_db(self):
        
        '''
        Function to update the PostgreSQL DB
        Adds row with initial data that doesn't change
        Updates row array fields with data with all entries
        '''

        super().__init__()
        

        # Iterating over XML and adding data to DB
        for rules in self.root.findall(self.rules):
            self.uuid = rules.get("uuid")
            rule = rules.get("name")

            
            try:

                self.negsrc = rules.find("negate-source").text

                if self.negsrc == 'yes':
                    self.negsrc = 'TRUE'
                else:
                    self.negsrc = 'FALSE'

            except AttributeError:
                self.negsrc = 'FALSE'

            try:

                self.negdst = rules.find("negate-destination").text

                if self.negdst == 'no':
                    self.negdst = "FALSE"
                else:
                    self.negdst = "TRUE"

            except AttributeError:
                self.negdst = 'FALSE'

            try:

                self.disabled = rules.find("disabled").text

                if self.disabled == 'no':
                    self.disabled = "FALSE"
                else:
                    self.disabled = "TRUE"

            except AttributeError:
                self.disabled = 'FALSE'

            self.action = rules.find("action").text

            self.excecute_sql( 
            "INSERT INTO" 
            " securityrules (rule_id, rulename, dgrp, negatesrc, negatedest, action, disabled)"
            " VALUES ("
            f"'{self.uuid}',"
            f"'{rule}',"
            f"'{self.dgrp}',"
            f"{self.negsrc},"
            f"{self.negdst},"
            f"'{self.action}',"
            f"{self.disabled})")

            for entry in self.ENTRIES:
                for info in self.root.findall(f".result/security/rules/entry/[@name='{rule}']/{entry}/member"):
                    
                    
                    self.excecute_sql(
                    "UPDATE securityrules"
                    f" SET {self.ENTRY_DICT[entry]} = {self.ENTRY_DICT[entry]}"
                    " || '{"+info.text+"}' WHERE rule_id =" 
                    f"'{self.uuid}'")

        self.close_connect(close_cur=False, close_DB=False, commit=True)
                        