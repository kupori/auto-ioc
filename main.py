from datetime import datetime
from openpyxl import load_workbook
import pandas as pd
import msoffcrypto, io, os, re, csv

#############################################################################################

# store respective classifed sheet names 
sheet_name_hashes = []
sheet_name_address = []
sheet_name_unknown = []

# holding list for extracted data
holding_list_hash = []
holding_list_address = []
holding_list_sheet_known = []

# store verified values for csv generation
hash_md5 = []
hash_sha1 = []
hash_sha256 =[]
hash_sha512 = []
hash_unknown = []

address_ip = []
address_url = []
address_unknown = []

# Common Sheet Names
v1 = [ "MD5", "SHA", "SHA1", "SHA256", "SHA512"]
v2 = ["IP", "Maicious_Domain(s)_IP"]
v3 = ["DOMAIN", "URL"]

# Blacklist Output- MD5, SHA1, SHA256, SHA512, Attacker IP, Target IP, URL 
output_classified = {"md5":[], "sha1":[], "sha256":[], "sha512":[], "ip":[], "url":[]}
output_unknown = {"hash":[], "ip/url":[], "sheet":[]}

#############################################################################################

# validate ipv4 format xxx.xxx.xxx.xxx (each xxx between 0 and 255)
def validate_ipv4(xd):
    a = xd.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

# Checks if file is password protected
def isExcelEncrypted(xd):
    try:
        fileHandle = open(xd, "rb")
        ofile = msoffcrypto.OfficeFile(fileHandle)
        isEncrypted = ofile.is_encrypted()
        fileHandle.close()
        return isEncrypted
    except Exception as err:
        return "Exception: "+ str( format(err) )

# extract sheetnames and save to list
def get_sheet_names(xd):
    wb2 = load_workbook(xd)
    sheet_name_list = wb2.sheetnames
    print ("\nSheet Names Found ---> {} " .format(sheet_name_list))
    return sheet_name_list

# extract data from first column of verified sheet names into a holding list
def extract_data(xd):
# Todo: detect substrings (if sheetname is SHA1 (v2), need to match SHA1)
    for i in xd:
        if i in v1:
            sheet_name_hashes.append(i)
        if i in v2:
            sheet_name_address.append(i)
        if (i not in v1) and (i not in v2):
            sheet_name_unknown.append(i)

    if len(sheet_name_hashes) > 0:
        for x in sheet_name_hashes:
            df = pd.read_excel(file_name, x)
            first_column = df.iloc[:, 0].tolist()
            holding_list_hash.extend(first_column)
    if len(sheet_name_address) > 0:
        for x in sheet_name_address:
            df = pd.read_excel(file_name, x)
            first_column = df.iloc[:, 0].tolist()
            holding_list_address.extend(first_column)
    if len(sheet_name_unknown) > 0:
        for x in sheet_name_unknown:
            df = pd.read_excel(file_name, x)
            first_column = df.iloc[:, 0].tolist()
            holding_list_sheet_known.extend(first_column)

    holding_list_hash_count = len(holding_list_hash)
    holding_list_address_count = len(holding_list_address)
    holding_list_sheet_known_count = len(holding_list_sheet_known)

    if holding_list_hash_count > 0:
        print ("Extracted {} potential hashes from Sheets {} " .format(holding_list_hash_count, sheet_name_hashes))
    if holding_list_address_count > 0:
        print ("Extracted {} potential ip/urls from Sheets {} " .format(holding_list_address_count, sheet_name_address))
    if holding_list_sheet_known_count > 0:
        print ("Extracted {} data from Unknown Sheets {} " .format(holding_list_sheet_known_count, sheet_name_unknown))
    
    return [holding_list_hash_count, holding_list_address_count, holding_list_sheet_known_count]

# classify data from the holding list into various lists using regex (md5, sha1, ip, url etc)
def process_data(xd):
    if xd[0] > 0:
        for i in holding_list_hash:
            if re.match(r"\b([a-f\d]{32}|[A-F\d]{32})\b", i):
                # hash_md5.append(i)
                output_classified["md5"].append(i)
            elif re.match(r"\b([a-f\d]{40}|[A-F\d]{40})\b", i):
                # hash_sha1.append(i)
                output_classified["sha1"].append(i)
            elif re.match(r"\b([a-f\d]{64}|[A-F\d]{64})\b", i):
                # hash_sha256.append(i)
                output_classified["sha256"].append(i)
            elif re.match(r"\b([a-f\d]{128}|[A-F\d]{128})\b", i):
                # hash_sha512.append(i)
                output_classified["sha512"].append(i)
            else:
                # hash_unknown.append(i)
                output_unknown["hash"].append(i)
            
        # if len(hash_md5) > 0:
        #     print ("MD5 ---> " + str(len(hash_md5)))
        # if len(hash_sha1) > 0:
        #     print ("SHA1 ---> " + str(len(hash_sha1)))
        # if len(hash_sha256) > 0:
        #     print ("SHA256 ---> " + str(len(hash_sha256)))
        # if len(hash_sha512) > 0:
        #     print ("SHA512 ---> " + str(len(hash_sha512)))
        # if len(hash_unknown) > 0:
        #     print ("Unknown -->" + str(len(hash_unknown)))

    if xd[1] > 0:
        # replace any [.] with . in the list
        clean_holding_list_address = [w.replace("[.]", ".") for w in holding_list_address]
        for i in clean_holding_list_address:
            # check if any . to remove invalid data like words and headers  
            if "." not in i:
                # address_unknown.append(i)
                output_unknown["ip/url"].append(i)
            # run ipv4 validate function
            elif validate_ipv4(i) is True:
                # address_ip.append(i)
                output_classified["ip"].append(i)
            # most likely a URL if not ipv4 [Needs testing]
            else:
                # address_url.append(i)
                output_classified["url"].append(i)
    
    if xd[2] > 0:
        output_unknown["sheet"].extend(holding_list_sheet_known)


    print ("\nClassified Extracted Data: ")
    for x in output_classified:
        entry_count = len(output_classified[x])
        if entry_count > 0:
            print ("{} --> {}" .format(x, entry_count))
        # if len(address_ip) > 0:
        #     print ("IPv4 ---> " + str(len(address_ip)))
        # if len(address_url) > 0:
        #     print ("URL ---> " + str(len(address_url)))
        # if len(address_unknown) > 0:
        #     print ("Unknown ---> " + str(len(address_unknown)))
    print ("\nUnknown Data:")
    for x in output_unknown:
        entry_count = len(output_unknown[x])
        if entry_count > 0:
            print ("{} --> {}" .format(x, entry_count))

def csv_generate():
    dtnow = datetime.now()
    dt_string = dtnow.strftime("%d-%m-%Y, %H%M%S")
    os.makedirs("auto-ioc-output ({})" .format(dt_string))
    pass
    

#############################################################################################

# Finds .xlsx file in directory
file_count = 0
for file in os.listdir("."):
    if file.endswith(".xlsx"):
        file_name = file
        file_count += 1

# If multiple .xslx file found, quit
if file_count > 1:
    print ("ERROR: Multiple xlsx files found, only one file can be processed, remove the rest and rerun the script")
    quit()

# If no file found, quit
if 'file_name' not in globals():
    print ("ERROR: No xlsx file found")
    quit()

# Ask for password if encrypted
if isExcelEncrypted(file_name) is True:
    temp = io.BytesIO()
    with open (file_name, 'rb') as f:
        excel = msoffcrypto.OfficeFile(f)
        excel.load_key(input("\n{} is encrypted, enter password: " .format(file_name)))
        excel.decrypt(temp)
        file_name = temp

        sheet_names = get_sheet_names(file_name)
        holding_list_counts = extract_data(sheet_names)
        process_data(holding_list_counts)
        csv_generate()
else:
    print ("\n{} is not encrypted, no password required" .format(file_name))
    sheet_names = get_sheet_names(file_name)
    holding_list_counts = extract_data(sheet_names)
    process_data(holding_list_counts)
    csv_generate()






