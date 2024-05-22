# Nmap Scan Importer

This tool will take a XML formatted nmap scan result, and ingest it into a SQLite3 database. Once ingested, users can query API endpoints to get back data on the imported results. The endpoints can be reached using command-line tools such as cURL or in a browser with the provided swagger API UI located at http://localhost:5000/api/docs.

## Design Theory

I decided to go with XML formatting for this project. There are numerous libraries in Python for parsing and converting XML data, and out of the provided formats, XML is the easiest to convert to a JSON structure. I ultimately decided to use the ElementTree class for XML parsing as it is included in the `xml` library which is native.

Scan data is stored in the database and ordered by a unique ID that is an MD5 sum of the XML data to prevent duplicate scan data.

All responses are JSON formatted. This gives the user freedom to further filter data how the see fit as JSON is an easily manipulatable format using Python's json.tool or `jq`.

The Swagger API UI uses boilerplate html/css/js files and is impletemented in the app with a custom openapi.json template and rendered using `render_template('swaggerui.html')`

#### Assumptions
At least 1 host will be present in all scan files.
Host IP address exists.
Port ID exists.
Protocol (tcp, udp) exists.
Port state (open, filtered, closed) exists.
Port state reason (no response, syn-ack, etc) exists.

All other fields are optional, and can hold null values.

#### Additional Thoughts
If I were building this app for a production environment, I'd much rather see it built using serverless technologies. Using a mix of API Gateway/Lambda/DynamoDB would yield much better results as it would be scalable, highly available and require little to no maintenence.

## Launching
#### Requirements
Below are the dependencies required to run this app.
```
docker
docker-compose
```
Optional to interact with the API via command-line.
```
curl
```
#### Versions
```
[abevil@epsilon bf_code_challenge]# docker-compose --version
docker-compose version 1.29.2, build unknown
[abevil@epsilon bf_code_challenge]# docker --version
Docker version 20.10.7, build f0df35096d
```
#### Startup
To start the up run `docker-compose up` in the directory containing the docker build files.
```
[abevil@epsilon bf_code_challenge]# ls
Dockerfile  app  docker-compose.yml  nmap.results.xml  requirements.txt  test_results.xml
[abevil@epsilon bf_code_challenge]# docker-compose up
<--cut for brevity-->
web_1  |  * Environment: production
web_1  |    WARNING: This is a development server. Do not use it in a production deployment.
web_1  |    Use a production WSGI server instead.
web_1  |  * Debug mode: off
web_1  |  * Running on all addresses.
web_1  |    WARNING: This is a development server. Do not use it in a production deployment.
web_1  |  * Running on http://172.18.0.2:5000/ (Press CTRL+C to quit)
```

Docker compose will attach the container to an internal network interface, however port 5000 is mapped from the host network to the container, so the app is accessible from http://localhost:5000/.
```
[abevil@epsilon bf_code_challenge]# curl -I http://localhost:5000/
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1484
Server: Werkzeug/2.0.1 Python/3.8.10
Date: Sun, 13 Jun 2021 17:59:58 GMT
```

## Interacting with API

#### API endpoints
| Path  | Method  | Description  |
| :------------ | :------------: | :------------ |
| /api/scans  | GET  | Get a listing of nmap scans stored in the database  |
| /api/scans/{ip}  | GET  | Get a listing of nmap scans filtered by host IP address  |
| /api/scans/{uid}  | GET  | Get a listing of nmap scans filtered by unique scan ID  |
| /api/upload  | POST  | Upload nmap scan data from an XML formatted nmap scan result file  |

#### cURL examples
##### Uploading data

Upload XML formatted nmap results.
```
[abevil@epsilon bf_code_challenge]# curl -X 'POST' 'http://localhost:5000/api/upload' -H 'accept: */*' -H 'Content-Type: application/octet-stream' --data-binary @nmap.results.xml
{"results":{"total_hosts":"40"},"status":"Success"}
```
##### Getting scan data
Get scan results for a specified host. Partial IP searches are supported as well.
```
[root@epsilon bf_code_challenge]# curl -s -X 'GET' 'http://localhost:5000/api/scans/ip/74.207.244.221' -H 'accept: */*' | python -m json.tool
[
    {
        "nmapid": "f6000da6c0c0af05d22bd8aa3916898a",
        "args": "nmap -T4 -A -p 1-1000 -oX - scanme.nmap.org",
        "scanned_hosts": 1,
        "elapsed_time": 13.66,
        "scans": [
            {
                "id": "f6000da6c0c0af05d22bd8aa3916898a",
                "host": "74.207.244.221",
                "host_dns": "scanme.nmap.org, li86-221.members.linode.com",
                "port": 22,
                "protocol": "tcp",
                "port_state": "open",
                "port_reason": "syn-ack",
                "service_name": "ssh",
                "port_script": "ssh-hostkey, 1024 8d:60:f1:7c:ca:b7:3d:0a:d6:67:54:9d:69:d9:b9:dd (DSA)\n                     2048 79:f8:09:ac:d4:e2:32:42:10:49:d3:bd:20:82:85:ec (RSA)",
                "ostype": "Linux 2.6.39",
                "uptime": "23450"
            },
            {
                "id": "f6000da6c0c0af05d22bd8aa3916898a",
                "host": "74.207.244.221",
                "host_dns": "scanme.nmap.org, li86-221.members.linode.com",
                "port": 80,
                "protocol": "tcp",
                "port_state": "open",
                "port_reason": "syn-ack",
                "service_name": "http",
                "port_script": "http-title, Go ahead and ScanMe!",
                "ostype": "Linux 2.6.39",
                "uptime": "23450"
            }
        ]
    }
]
```

Get scan results for a specified unique scan ID.
```
[root@epsilon bf_code_challenge]# curl -s -X 'GET' 'http://localhost:5000/api/scans/uid/f6000da6c0c0af05d22bd8aa3916898a' -H 'accept: */*' | python -m json.tool
[
    {
        "nmapid": "f6000da6c0c0af05d22bd8aa3916898a",
        "args": "nmap -T4 -A -p 1-1000 -oX - scanme.nmap.org",
        "scanned_hosts": 1,
        "elapsed_time": 13.66,
        "scans": [
            {
                "id": "f6000da6c0c0af05d22bd8aa3916898a",
                "host": "74.207.244.221",
                "host_dns": "scanme.nmap.org, li86-221.members.linode.com",
                "port": 22,
                "protocol": "tcp",
                "port_state": "open",
                "port_reason": "syn-ack",
                "service_name": "ssh",
                "port_script": "ssh-hostkey, 1024 8d:60:f1:7c:ca:b7:3d:0a:d6:67:54:9d:69:d9:b9:dd (DSA)\n                     2048 79:f8:09:ac:d4:e2:32:42:10:49:d3:bd:20:82:85:ec (RSA)",
                "ostype": "Linux 2.6.39",
                "uptime": "23450"
            },
            {
                "id": "f6000da6c0c0af05d22bd8aa3916898a",
                "host": "74.207.244.221",
                "host_dns": "scanme.nmap.org, li86-221.members.linode.com",
                "port": 80,
                "protocol": "tcp",
                "port_state": "open",
                "port_reason": "syn-ack",
                "service_name": "http",
                "port_script": "http-title, Go ahead and ScanMe!",
                "ostype": "Linux 2.6.39",
                "uptime": "23450"
            }
        ]
    }
]
```

Get all scan results. Can be filtered with `max_results` query parameter (default 5). Filtering max results will return a limited set of scans, but will include all hosts of each returned scan.
```
[root@epsilon bf_code_challenge]# curl -s -X 'GET' 'http://localhost:5000/api/scans' -H 'accept: */*' | python -m json.tool
[
    {
        "nmapid": "518a0b125cb9a2b35c4ffc21a7a9749e",
        "args": "nmap -Pn -p80,443,8443,5000,8080 -iL ips.txt -oA nmap.results -vvvvv",
        "scanned_hosts": 40,
        "elapsed_time": 13.95,
        "scans": [
		<--------------cut for brevity-------------->
            {
                "id": "518a0b125cb9a2b35c4ffc21a7a9749e",
                "host": "81.107.115.203",
                "host_dns": "cpc123026-glen5-2-0-cust970.2-1.cable.virginm.net",
                "port": 80,
                "protocol": "tcp",
                "port_state": "open",
                "port_reason": "syn-ack",
                "service_name": "http",
                "port_script": "",
                "ostype": "",
                "uptime": ""
            }
		]
	},
	{
        "nmapid": "f6000da6c0c0af05d22bd8aa3916898a",
        "args": "nmap -T4 -A -p 1-1000 -oX - scanme.nmap.org",
        "scanned_hosts": 1,
        "elapsed_time": 13.66,
        "scans": [
            {
                "id": "f6000da6c0c0af05d22bd8aa3916898a",
                "host": "74.207.244.221",
                "host_dns": "scanme.nmap.org, li86-221.members.linode.com",
                "port": 22,
                "protocol": "tcp",
                "port_state": "open",
                "port_reason": "syn-ack",
                "service_name": "ssh",
                "port_script": "ssh-hostkey, 1024 8d:60:f1:7c:ca:b7:3d:0a:d6:67:54:9d:69:d9:b9:dd (DSA)\n                     2048 79:f8:09:ac:d4:e2:32:42:10:49:d3:bd:20:82:85:ec (RSA)",
                "ostype": "Linux 2.6.39",
                "uptime": "23450"
            },
            {
                "id": "f6000da6c0c0af05d22bd8aa3916898a",
                "host": "74.207.244.221",
                "host_dns": "scanme.nmap.org, li86-221.members.linode.com",
                "port": 80,
                "protocol": "tcp",
                "port_state": "open",
                "port_reason": "syn-ack",
                "service_name": "http",
                "port_script": "http-title, Go ahead and ScanMe!",
                "ostype": "Linux 2.6.39",
                "uptime": "23450"
            }
        ]
    }
]
```
