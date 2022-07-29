import requests
import urllib3
import sys
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)

def load_esm_creds(xd): 
	with open (xd, "r") as f:
		creds = [next(f).strip() for i in range(2)]
		if len(creds) == 2 and type(creds) is not None:
			return creds
		else:
			print ("Error Retrieving ESM Credentials from file")
			logging.info("Error Retrieving ESM Credentials from file")
			sys.exit()

def load_resource_ids(xd):
	with open (xd, "r") as f:
		index = 0
		dict_output = {}
		data = f.read()
		to_list = data.split("\n")
		to_list = [x.strip() for x in to_list]
		for i in to_list:
			if index % 2 == 0:
				dict_output[i] = to_list[index+1]
			index += 1
		return (dict_output)

def load_esm_hostnames(xd):
    with open(xd, "r") as f:
        data = f.read()
        to_list = data.split("\n")
        to_list = [x.strip() for x in to_list]
        return to_list

def get_auth_token(usr, pw, esm): 
	try:
		url = "https://{}:8443/www/core-service/rest/LoginService/login?login={}&password={}&alt=json" .format(esm, usr, pw)
		r = requests.get(url, verify=False)
		values = r.json()
		authToken = values['log.loginResponse']['log.return']
		return authToken
	except Exception as e:
		if str(e)  == "Expecting value: line 1 column 2 (char 1)":
			print ("Login Error ---> Invalid usr/pw")
			logging.info("Login Error ---> Invalid usr/pw")
		else: 
			print ("Login Error ---> {}".format(e))
			logging.info(("Login Error ---> {}".format(e)))


def add_entries(esm_hostname, authToken, resource_id, column_name_list, ioc_entries):
	
	jsoninput="""{
	"act.addEntries" : {
	"act.authToken" : '""" + authToken + """',
	"act.resourceId" : '""" + resource_id + """',
	"act.entryList" :
			{
			"columns": ['""" + column_name_list + """'],
        	"entryList": [
				""" + ioc_entries + """
			]
			}
		}
	} 
	"""
	# print (jsoninput)
	headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
	url = "https://{}:8443/www/manager-service/rest/ActiveListService/addEntries" .format(esm_hostname)
	r = requests.post(url,verify=False, data=jsoninput, headers=headers)
	print ("{} - {} ---> {}" .format(esm_hostname, column_name_list, r))
	logging.info("{} - {} ---> {}" .format(esm_hostname, column_name_list, r))

def delete_entries(esm_hostname, authToken, resource_id, column_name_list, ioc_entries):
	
	jsoninput="""{
	"act.deleteEntries" : {
	"act.authToken" : '""" + authToken + """',
	"act.resourceId" : '""" + resource_id + """',
	"act.entryList" :
			{
			"columns": ['""" + column_name_list + """'],
        	"entryList": [
				""" + ioc_entries + """
			]
			}
		}
	} 
	"""
	# print (jsoninput)
	headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
	url = "https://{}:8443/www/manager-service/rest/ActiveListService/deleteEntries" .format(esm_hostname)
	r = requests.post(url,verify=False, data=jsoninput, headers=headers)
	print ("{} - {} ---> {}" .format(esm_hostname, column_name_list, r))
	logging.info("{} - {} ---> {}" .format(esm_hostname, column_name_list, r))

def get_activelist_entries(esm_hostname, authToken, resource_id):

	jsoninput="""{
	"act.getEntries" : {
	"act.authToken" : '"""+ authToken +"""',
	"act.resourceId" : '""" + resource_id + """'
	}
	}"""
	headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
	url = "https://{}:8443/www/manager-service/rest/ActiveListService/getEntries" .format(esm_hostname)
	r = requests.post(url, verify=False, data=jsoninput, headers=headers)
	values = r.json()
	return values['act.getEntriesResponse']['act.return']['entryList']


def logout(esm_hostname, authToken): 
	try:
		url = "https://{}:8443/www/core-service/rest/LoginService/logout?authToken={}&alt=json" .format(esm_hostname, authToken)
		requests.get(url, verify=False)
		print ("Logout of {}" .format(esm_hostname))
		logging.info("Logout of {}" .format(esm_hostname))
	except Exception as e:
		print ("Logout Error ---> {}".format(e))
		logging.info("Logout Error ---> {}".format(e))