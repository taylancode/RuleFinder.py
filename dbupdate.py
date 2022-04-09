from rulefinder import Rulefinder
from sqlmanager import SQL

# Local file for variables
import constants

'''
Database update script

Flow is as follows:
Re-make SQL table ->
API call to device group to get rules ->
Iterate over data and adds to table ->
Commit DB changes

Closes connection when all device groups have been done
'''


def main(fw, key, dgrp):
    
    # Calling the update db function that handles the data iteration and SQL table update
    initfinder = Rulefinder(fw=fw, key=key, dgrp=dgrp)
    initfinder.update_db()


if __name__ == '__main__':

    # Get variables
    fw = constants.FW
    key = constants.PA_KEY

    # Initiate SQL manager
    dbinit = SQL()

    # Re-make the table before running the update
    dbinit.excecute_sql(sql=
        """DROP TABLE IF EXISTS securityrules;

        CREATE TABLE securityrules (
        rule_id UUID PRIMARY KEY,
        rulename TEXT,
        dgrp TEXT,
        fromzone TEXT[],
        tozone TEXT[],
        sourceip TEXT[],
        sourceusr TEXT[],
        destip TEXT[],
        category TEXT[],
        application TEXT[],
        service TEXT[],
        negatesrc BOOLEAN NOT NULL,
        negatedest BOOLEAN NOT NULL,
        action TEXT NOT NULL,
        disabled BOOLEAN NOT NULL);

        commit""")

    # Update for every device group in list
    for dgrps in constants.DGROUPS:
        dgrp = dgrps
        
        main(fw, key, dgrp)
    
    # Commit and close Cursor/DB connections
    dbinit.close_connect(close_cur=True, close_DB=True, commit=True)