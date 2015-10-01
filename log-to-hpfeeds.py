
#!/usr/bin/python
#smerig maar werkt 
import time, os,hpfeeds
import datetime
import json

def get_hpfeeds_client():
	host = "IP"
	port = 10000
	identity = "resolver.aasd"
	secret = "geheim"
	channel = "resolver.events"

	hpc = None
	hpc = hpfeeds.new(
	host,
	int(port),
	identity,
	secret
	)
	hpc.s.settimeout(0.01)
	return hpc


def logStringToJSON(line):
	logarray = line.split()
	attackType = None
	victimIP = None
	honeyIP = None
	victimPort = None
	attackerPort = None
	for item in logarray:
		if "ATTACKTYPE" in item:
			attackType = item.split('=')[1]
		elif "SRC" in item:
			victimIP = item.split('=')[1]
		elif "DST" in item:
			honeyIP = item.split('=')[1]
		elif "DPT" in item:
			victimPort = item.split('=')[1]
		elif "SPT" in item:
			attackerPort = item.split('=')[1]
			
	if (attackType is None) or (victimIP is None) or (honeyIP is None) or (victimPort is None) or (attackerPort is None):
		return False
	else:
		return {
		'attackType': attackType,
		'honeyIP' : honeyIP,
		'victimIP' : victimIP,
		'attackerPort' : attackerPort,
		'victimPort' : victimPort
		}

def logData(request, hpclient):
	if hpclient:
		req = json.dumps(request)
		hpclient.publish("resolver.events", req)


filename = '/var/log/iptables.log'
file = open(filename,'r')

filestats = os.stat(filename)
filesize = filestats[6]
file.seek(filesize)

hpc = get_hpfeeds_client()

while 1:
        where = file.tell()
        line = file.readline()
        if not line:
                time.sleep(1)
                file.seek(where)
        else:
             	newline = logStringToJSON(line)
		if newline == False:
			print "error converting to json"
		else:
			logData(newline, hpc)
               	print newline
