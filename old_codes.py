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

def getResourcesByIds(authToken, Ids): # not working
	
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


# list_activelist = get_activelists(authToken)
# string_activelist = stringify_list(list_activelist)
# print ("Retrieved ActiveLists Resource IDs")
# activeListDetails = getResourcesByIds(authToken, string_activelist)

# for activeList in activeListDetails:
    # 	print (activeList['reference']['id'] + " " + activeList['reference']['uri'])