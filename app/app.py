from flask import Flask, request, render_template
from connections import Connections
from xml.etree.ElementTree import ParseError
import json, hashlib
import xml.etree.ElementTree as ET


app = Flask(__name__)
db = Connections('database/nmap_data.db')

@app.route('/api/docs', methods=['GET'])
def get_docs(): #API UI frontend
    return render_template('swaggerui.html')

def scan_lookup(uid=None, host_ip=None, max_results=None): #Lookup scan info filtered by user input
    if host_ip or uid:
        result = db.search_host(host_ip, uid)
    else:
        result = db.get_scans(max_results)

    response = []
    #Create list of hosts with unique ids
    result = {v['id']:v for v in result}.values()
    for scan in result:
        nmapscan = {}
        metadata = db.get_metadata(scan['id'])
        nmapscan['nmapid'] = scan['id']
        nmapscan['args'] = metadata[0]['args']
        nmapscan['scanned_hosts'] = metadata[0]['num_hosts']
        nmapscan['elapsed_time'] = metadata[0]['elapsed_time']
        if host_ip: #Limit host responses to those matching IP filter
            nmapscan['scans'] = db.search_host(host_ip, uid=scan['id'])
        else:
            nmapscan['scans'] = db.search_host_by_uid(scan['id'])

        response.append(nmapscan)

    if response == []:
        return {'Status': 'Failed', 'Reason': 'Scan not found'}, 404
    else:
        return json.dumps(response)

@app.route('/api/scans', methods=['GET'])
def get_scans(): #Get a list of all scans. Can be filtered with max_results argument (default 5)
    max_results_arg = request.args.get('max_results')
    max_results = 5 if not max_results_arg else max_results_arg

    return scan_lookup(max_results=max_results)

@app.route('/api/scans/ip/<host_ip>', methods=['GET'])
def get_scans_by_ip(host_ip): #Get a list of scans on a specific host
    assert host_ip == request.view_args['host_ip']
    return scan_lookup(host_ip=host_ip)

@app.route('/api/scans/uid/<uid>', methods=['GET'])
def get_scans_by_uid(uid): #Get a full scan report
    assert uid == request.view_args['uid']
    return scan_lookup(uid=uid)


@app.route('/api/upload', methods=['POST'])
def upload_data(): #Upload nmap scan file. Accepts Application/octet-stream
    data = request.get_data(as_text=True)

    try:
        root = ET.fromstring(data)
    except ParseError:
        return {'status': 'Failed', 'reason': 'Malformed XML'}, 400
    
    #Generate UID from hash of data to prevent duplicate entries
    uid = hashlib.md5(data.encode()).hexdigest()
    hosts = root.findall('host')
    nmap_args = root.attrib['args']
    num_hosts = root.find('runstats').find('hosts').attrib['total']
    elapsed_time = root.find('runstats').find('finished').attrib['elapsed']

    response = {
            'status': '',
            'results': {}
    }

    if db.check_duplicate(uid): #Check database for duplicate scan results
        response['status'] = 'Failed'
        response['reason'] = 'Duplicate scan entry'
        return response, 406

    db.insert_metadata(uid, elapsed_time, nmap_args, num_hosts)

    payload = {}
    for host in hosts: #Pack data into dictionary to load into database
        for port in host.findall('ports')[0].findall('port'):
            payload['id'] = uid
            payload['host_ip'] = host.find('address').attrib['addr']
            payload['host_dns'] = ', '.join([name.attrib['name'] for name in host.find('hostnames')])
            payload['port_id'] = port.attrib['portid']
            payload['protocol'] = port.attrib['protocol']
            payload['port_state'] = port.find('state').attrib['state']
            payload['port_reason'] = port.find('state').attrib['reason']
            payload['service_name'] = port.find('service').attrib['name']
            #These items are not included in all scans, and will throw various errors if they don't exist
            try:
                payload['port_script'] = ', '.join([val for val in port.findall('script')[0].attrib.values()])
            except (IndexError, KeyError, AttributeError):
                payload['port_script'] = ''
            try:
                payload['ostype'] = host.find('os').find('osmatch').attrib['name']
            except (IndexError, KeyError, AttributeError):
                payload['ostype'] = ''
            try:
                payload['uptime'] = host.find('uptime').attrib['seconds']
            except (IndexError, KeyError, AttributeError):
                payload['uptime'] = ''

            result = db.insert_scan(payload)

    response['status'] = 'Success'
    response['results']['total_hosts'] = num_hosts

    return response
