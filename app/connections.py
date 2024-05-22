from sqlite3 import OperationalError
import sqlite3, json

class Connections:

    def __init__(self, db_path):
        self.db_path = db_path

        #Build fresh database if none found
        try:
            sqlite3.connect('file:{}?mode=rw'.format(self.db_path), uri=True)
        except OperationalError:
            self.build_db(self.db_path)

    def build_db(self, db_path): #Create new database
        connection = sqlite3.connect(self.db_path)
        cursor = connection.cursor()

        cursor.execute('create table metadata ( id char(36) not null, args char(100), elapsed_time float, num_hosts int )')
        cursor.execute('create table results ( id chat(36) not null, host char(50) not null, host_dns char(100), port int not null, protocol char(50) not null, port_state char(50) not null, port_reason char(50) not null, service_name char(50), port_script char(500), ostype char(50), uptime char(50) )')
        connection.commit()
        connection.close()

    def execute(self, query, args=()):
        #Args are passed in as a tuple and use DB-API parameter substitution to protect against SQL injection
        #https://docs.python.org/3.8/library/sqlite3.html
        connection = sqlite3.connect(self.db_path)
        cursor = connection.cursor()
        #Return query, cursor, and connection objects. cursor.description contains column names
        return cursor.execute(query, args), cursor, connection

    def format_response(self, data, cursor): #Format all sql responses into a more easily manipulatble format
        items = []
        for row in data:
            items.append({key:value for key, value in zip([key[0] for key in cursor.description], [column for column in row])})

        return items

    def check_duplicate(self, uid): #Check metadata table for duplicate nmap scan results
        result, cursor, connection = self.execute('select id from metadata where id = ?', (uid,))

        try:
            #If there's any objects in the list, a scan result with the same hash already exists
            [x for x in result][0][0]
            return True
        except IndexError:
            return False

    def get_scans(self, max_results): #Get a list of all scan IDs
        result, cursor, connection = self.execute('select id from metadata limit ?', (max_results,))
        return self.format_response(result, cursor)

    def get_metadata(self, uid): #Get metadata columns for a given ID
        result, cursor, connection = self.execute('select * from metadata where id = ?', (uid,))
        return self.format_response(result, cursor)

    def get_hosts(self, max_results):
        result, cursor, connection = self.execute('select distinct id, host from results limit ?', (max_results,))
        return self.format_response(result, cursor)

    def search_host(self, host_ip=None, uid=None): #Search for host by host_ip, uid, or both
        if uid and host_ip:
            #Using 'like' instead of and equal operator allows for partial IP searches
            result, cursor, connection = self.execute('select * from results where host like ? and id = ?', (host_ip + '%', uid))
        elif host_ip and not uid:
            result, cursor, connection = self.execute('select * from results where host like ?', (host_ip + '%',))
        elif uid and not host_ip:
            result, cursor, connection = self.execute('select * from results where id = ?', (uid,))
        return self.format_response(result, cursor)

    def search_host_by_uid(self, uid): #Search for host entries based on ID
        result, cursor, connection = self.execute('select * from results where id = \'{}\''.format(uid))
        return self.format_response(result, cursor)

    def insert_scan(self, data): #Insert data from uploaded scan file into database
        result, cursor, connection = self.execute('insert into results ( id, host, host_dns, port, protocol, port_state, port_reason, service_name, port_script, ostype, uptime ) values ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )', (data['id'], data['host_ip'], data['host_dns'], int(data['port_id']), data['protocol'], data['port_state'], data['port_reason'], data['service_name'], data['port_script'], data['ostype'], data['uptime']))
        connection.commit()
        connection.close()
        return

    def insert_metadata(self, uid, elapsed_time, nmap_args, num_hosts):
        result, cursor, connection = self.execute('insert into metadata ( id, elapsed_time, args, num_hosts ) values ( ?, ?, ?, ? )', (uid, float(elapsed_time), nmap_args, int(num_hosts)))
        connection.commit()
        connection.close()
        return
