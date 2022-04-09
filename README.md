# RuleFinder - Palo Alto Utility
This is a utility built to work with the Palo Alto firewall management system (Panorama).
It provides the ability to search for any IP/FQDN and find all associated security rules.
![Demo gif](./demo/demo.gif)

# Technologies
Built using:
Python
PostgreSQL
Flask/Jinja
HTML/CSS

# Inspiration
For anyone unfamiliar with Palo Alto firewalls or managing security rules in general,
there are potentially thousands of rules in any one environment with probably 10x 
more actual objects to be used in said rules. Panorama in this case does give the
ability to search for rules associated with objects but there are a few steps involved. 
For an admin this is not necessarily needed but I've been asked many times to provide
a list of rules for a list of servers and this can be time consuming. With this app,
not only can they search for themselves, it also is much faster than doing it manually. 

# Usage
This isn't really a production ready app since it doesn't have a login functionality 
and there are still some features missing (such as searching for associated address groups)
but if you would like to build on it, here's what you'll need:
`
### Apps:
PostgreSQL Database 
Python

## Modules:
requests
xml.etree.ElementTree
ipaddress
socket
re

## Files:

### constants.py:
FLASK_KEY = 'YOUR FLASK KEY'

FW = 'YOUR PANORAMA IP/FQDN'
PA_KEY = 'YOUR API KEY FOR PANORAMA'

DGROUPS = ['ALL DEVICE GROUPS YOU WANT TO QUERY']

### database.ini:

[postgresql]
host=localhost (OR WHEREVER THE DB IS HOSTED)
database=YOUR DB NAME
user=YOUR DB USER
password=YOUR DB PASSWORD
`