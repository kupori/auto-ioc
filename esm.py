import os, requests, urllib3, json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)

def load_creds(xd): # working
	try:
		if os.stat(xd).st_size == 0:
			raise Exception ("{} is Empty" .format(xd))
		with open (xd, "r") as f:
			creds = [next(f).strip() for i in range(2)]
			if len(creds) == 2:
				print ("Credentials ---> {} - {}" .format(creds[0], creds[1]))
				return creds
	except Exception as e:
		print ("Error loading credentials ---> {}".format(e))

def login(usr, pw): # working
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

def logout(authToken): # working
	try:	
		requests.get('https://esm72:8443/www/core-service/rest/LoginService/logout?authToken='+authToken+'&alt=json', verify=False)
		print ("Logout Successful")
	except Exception as e:
		print ("Logout Error ---> {}".format(e))

def get_activelists(authToken): # working
	r = requests.get('https://esm72:8443/www/manager-service/rest/ActiveListService/findAllIds?authToken='+authToken+'&alt=json', verify=False)
	values = r.json()
	return values['act.findAllIdsResponse']['act.return']

def stringify_list(ids): # working 
	id_string = ""
	for x in ids:
		id_string += "'" + str(x) + "'"
		id_string += ","
	id_string = id_string[:-1] # removes the , after the final entry
	return id_string

def getResourcesByIds(authToken, Ids):
	
	jsoninput="""{
	"act.getResourcesByIds" : {
	"act.authToken" : '""" + authToken +"""',
	"act.ids" : [ """+ Ids +""" ]
	}
	}"""

	headers = {'Content-Type': 'application/json'}
	r = requests.post('https://esm72:8443/www/manager-service/rest/ActiveListService/getResourcesByIds?alt=json', verify=False, data=jsoninput, headers=headers)
	values = r.json()
	return values['act.getResourcesByIdsResponse']['act.return']
	

if __name__ == "__main__":
	cr = load_creds("esm_c.txt")
	authToken = login(cr[0], cr[1])
	if authToken:
		print ("Login Successful")
		list_activelist = get_activelists(authToken)
		string_activelist = stringify_list(list_activelist)
		print ("Retrieved ActiveLists Resource IDs")
		# activeListDetails = getResourcesByIds(authToken, string_activelist)

		# for activeList in activeListDetails:
			# 	print (activeList['reference']['id'] + " " + activeList['reference']['uri'])
		logout(authToken)
		print ("Script Ended")
	# else:
	# 	print ("Script Ended")
	# 	input('Press Enter to Exit...')

