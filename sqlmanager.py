'''
PostgresSQL Manager
SQL manager to execute queries
Config for database handled by config.py
'''

import psycopg2
from config import config

class SQL:

    def __init__(self):

        # Set var to None to keep DB connection alive
        self.db_con = None

        try:
            
            if not self.db_con:
                # Read connection parameters
                params = config()

                # Connect to the PostgreSQL server
                self.db_con = psycopg2.connect(**params)
                
                # Create a cursor
                self.cur = self.db_con.cursor()

        except (Exception, psycopg2.DatabaseError) as error:
            print(error)


    def excecute_sql(self, sql: str, *args: str) -> str:
        
        # Executes sql query passed to function
        self.cur.execute(sql, *args)

        # Returns result if SELECT query
        try:
            result = self.cur.fetchall()
            return result
        except psycopg2.ProgrammingError:
            pass
        

    def close_connect(self, close_cur: bool, close_DB: bool, commit: bool):
        
        if commit is True:
            self.db_con.commit()
            print("Commited to Database...")
        
        # Close cursor
        if close_cur is True:
            self.cur.close()
            print("Cursor closed...")

        # Commit changes and close DB connection
        if close_DB is True:
            self.db_con.close()
            print("Database closed...")
