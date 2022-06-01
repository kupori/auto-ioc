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
		print ("Logout Successful")
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


if __name__ == "__main__":
	cr = load_creds("esm_c.txt")
	authToken = login(cr[0], cr[1])
	if authToken:
		print ("Login Successful")
		entries = get_activelist_entries(authToken, "xxxx") # saves into a list type containing json format

		for i in range (5):
			print (entries[i])

		logout(authToken)
		print ("Script Ended Without Errors")
	else:
		print ("Script Ended Due to Error")
		input('Press Enter to Exit...')
