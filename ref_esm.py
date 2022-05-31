import requests
import os
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)
installloc = os.getcwd() + "/"


def authenticate():
	#Get login token
	r = requests.get('https://esm72:8443/www/core-service/rest/LoginService/login?login=username&password=password&alt=json', verify=installloc+'esm.crt')
	values = r.json()
	authToken = values['log.loginResponse']['log.return']
	return authToken

def logout(authToken):
	r = requests.get('https://esm72:8443/www/core-service/rest/LoginService/logout?authToken='+authToken+'&alt=json', verify=installloc+'esm.crt')

def reformatList(Ids):
	IdsString = ""
	for Id in Ids:
		IdsString += str(Id)
		IdsString += "', '"
	IdsString = IdsString[:-4]
	return IdsString	

def getResourcesByIds(authToken, Ids):
	noneUnicodeIds = reformatList(Ids)
	jsoninput="""{
	"act.getResourcesByIds" : {
	"act.authToken" : '"""+ authToken +"""',
	"act.ids" : [ '"""+ noneUnicodeIds + """' ]
	}
	}"""
	headers = {'Content-Type': 'application/json'}
	r = requests.post('https://esm72:8443/www/manager-service/rest/ActiveListService/getResourcesByIds?alt=json', verify=installloc+'esm.crt', data=jsoninput, headers=headers)
	values = r.json()
	print (values)
	return values['act.getResourcesByIdsResponse']['act.return']
	
def listActiveLists(authToken):
	r = requests.get('https://esm72:8443/www/manager-service/rest/ActiveListService/findAllIds?authToken='+authToken+'&alt=json', verify=installloc+'esm.crt')
	values = r.json()
	return values['act.findAllIdsResponse']['act.return']
	

if __name__ == "__main__":
	authToken = authenticate()
	activeLists = listActiveLists(authToken)
	activeListDetails = getResourcesByIds(authToken, activeLists)

	for activeList in activeListDetails:
		print (activeList['reference']['id'] + " " + activeList['reference']['uri'])
		logout(authToken)