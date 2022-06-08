import os, requests, urllib3, sys, json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)

def load_creds(xd): 
	with open (xd, "r") as f:
		creds = [next(f).strip() for i in range(2)]
		if len(creds) == 2 and type(creds) is not None:
			print ("Login via {}" .format(creds[0]))
			return creds
		else:
			print("Error Retrieving Credentials")
			sys.exit()

def login(usr, pw): 
	try:
		login_link = "https://esm72:8443/www/core-service/rest/LoginService/login?login={}&password={}&alt=json" .format(usr, pw)
		r = requests.get(login_link, verify=False)
		values = r.json()
		authToken = values['log.loginResponse']['log.return']
		return authToken
	except Exception as e:
		if str(e)  == "Expecting value: line 1 column 2 (char 1)":
			print ("Login Error ---> Invalid usr/pw")
		else: 
			print ("Login Error ---> {}".format(e))

def logout(authToken): 
	try:	
		requests.get('https://esm72:8443/www/core-service/rest/LoginService/logout?authToken='+authToken+'&alt=json', verify=False)
		print ("\nLogout Successful")
	except Exception as e:
		print ("Logout Error ---> {}".format(e))


def get_activelist_entries(authToken, resource_id):

	jsoninput="""{
	"act.getEntries" : {
	"act.authToken" : '"""+ authToken +"""',
	"act.resourceId" : '""" + resource_id + """'
	}
	}"""
	headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
	r = requests.post('https://esm72:8443/www/manager-service/rest/ActiveListService/getEntries', verify=False, data=jsoninput, headers=headers)
	values = r.json()
	return values['act.getEntriesResponse']['act.return']['entryList']

def add_hash_entries(authToken, resource_id, column_name_list, test_value):
	
	jsoninput="""{
	"act.addEntries" : {
	"act.authToken" : '""" + authToken + """',
	"act.resourceId" : '""" + resource_id + """',
	"act.entryList" :
			{
			"columns": """+ str(column_name_list)+""",
        	"entryList": [
				{
				"entry": ['"""+ test_value +"""', '']
				}
			]
			}
		}
	} 
	"""
	print (jsoninput)
	headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
	requests.post('https://esm72:8443/www/manager-service/rest/ActiveListService/addEntries', verify=False, data=jsoninput, headers=headers)

def add_url_entries(authToken, resource_id, test_value):
	
	jsoninput="""{
	"act.addEntries" : {
	"act.authToken" : '""" + authToken + """',
	"act.resourceId" : '""" + resource_id + """',
	"act.entryList" :
        {"entryList": {"entry": ['"""+ test_value +"""']
					}
				}
			}
	} 
	"""
	print (jsoninput)
	headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
	requests.post('https://esm72:8443/www/manager-service/rest/ActiveListService/addEntries', verify=False, data=jsoninput, headers=headers)


if __name__ == "__main__":

	hash_list = ["MD5", "File Name"]
	hash_value = "testhash1234md5"
	hash_resource_id = "H7xTtNoEBABCvHWAZJAFnGQ=="

	url_value = "andrewtest.com"
	url_resource_id = "HF+HwNoEBABCvJKJCmg7g6w=="

	cr = load_creds("esm_c.txt")
	auth_token = login(cr[0], cr[1])
	if auth_token:
		print ("Login Successful")
		
		add_hash_entries(auth_token, hash_resource_id, hash_list, hash_value)
		hash_entries = get_activelist_entries(auth_token, hash_resource_id) # saves into a list type containing json format
		print ("\n MD5 ActiveList Entries:\n")
		for i in hash_entries:
			print (i)


		# add_url_entries(auth_token, url_resource_id, url_value)
		# url_entries = get_activelist_entries(auth_token, url_resource_id)
		# print ("\n URL ActiveList Entries:\n")
		# for i in url_entries:
		# 	print (i)
		

		logout(auth_token)
		print ("\nScript Ended Without Errors")
	else:
		print ("Script Ended Due to Error")
		input('Press Enter to Exit...')
