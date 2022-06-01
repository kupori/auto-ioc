import requests
import os
import json
import csv
from itertools import islice
from requests.packages.urllib3.exceptions import SubjectAltNameWarning
requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)
installloc = os.getcwd() + "/"

def authenticate():
	#Get login token
	r = requests.get('https://esm:8443/www/core-service/rest/LoginService/login?login=api&password=password&alt=json', verify=installloc+'esm.crt')
	values = r.json()
	#values = r.text
        authToken = values['log.loginResponse']['log.return']
	return authToken
        #return values

def logout(authToken):
	r = requests.get('https://esm:8443/www/core-service/rest/LoginService/logout?authToken='+authToken+'&alt=json', verify=installloc+'esm.crt')
	
def getEntries(authToken, resourceId):
	jsoninput="""{
	"act.getEntries" : {
	"act.authToken" : '"""+ authToken +"""',
	"act.resourceId" : '""" + resourceId + """'
	}
	}"""
	headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
	r = requests.post('https://esm:8443/www/manager-service/rest/ActiveListService/getEntries', verify=installloc+'esm.crt', data=jsoninput, headers=headers)
	values = r.json()
        jsonvalues = json.dumps(values['act.getEntriesResponse']['act.return']['columns'], sort_keys=True, indent=4)
	return len(values['act.getEntriesResponse']['act.return']['columns']), jsonvalues

def addEntries(authToken, resourceId, col_names, csv_values):
        csv_value_string = ""
        for value in csv_values:
            csv_value_string+="{"
            csv_value_string+=""" "entry": """
            csv_value_string+=str(value)
            csv_value_string+="},\n"

        jsoninput="""{
	"act.addEntries" : {
	"act.authToken" : '""" + authToken + """',
	"act.resourceId" : '""" + resourceId + """',
	"act.entryList" :
        {
            "columns": """+col_names+""",
            "entryList": [
                """+csv_value_string+"""
            ]
	}
        }
       } 
	"""
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
	r = requests.post('https://esm:8443/www/manager-service/rest/ActiveListService/addEntries', verify=installloc+'esm.crt', data=jsoninput, headers=headers)
        values = r.text
	return values

def readCSV(csvToRead):
    print "[+] Loading " + csvToRead
    with open(csvToRead, 'rb') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        col_count=len(next(reader))
        print "[+] " + str(col_count) + " column(s) identified"
        csvfile.seek(0)
        data = list(reader)
        row_count = len(data)
        print "[+] " + str(row_count) + " row(s) identified"
        if row_count > 5:
            row_count = 5
        print "[+] Printing first " + str(row_count) + " lines ... "
        csvfile.seek(0)
        for x in range (0, row_count):
            print next(reader)
        return col_count, data


csv_col_count, csv_values = readCSV(installloc+'/toadd.csv')
authToken = authenticate()

al_col_count, json_values = getEntries(authToken, "HRGaky2ABABCL9M8amUoLtg==")
if csv_col_count != al_col_count:
    print "[-] Number of columns don't match ... exiting!"
    exit(0)
else:
    print "[+] Number of columns match!"

print addEntries(authToken, "HRGaky2ABABCL9M8amUoLtg==", json_values, csv_values)
logout(authToken)