import pandas as pd
import msoffcrypto
from openpyxl import load_workbook
import io
import os
import re

#############################################################################################

# store respective classifed sheet names 
sheet_name_address = []
sheet_name_hashes = []
sheet_name_unknown = []

# holding list for extracted data
holding_list_hash = []
holding_list_address = []

# store verified values for csv generation
hash_md5 = []
hash_sha1 = []
hash_sha256 =[]
hash_sha512 = []
address_ip = []
address_domain = []

# Blacklist Output- MD5, SHA1, SHA256, SHA512, Attacker IP, Target IP, URL 

# Common Sheet Names
v1 = [ "MD5", "SHA", "SHA1", "SHA256", "SHA512"]
v2 = ["IP", "DOMAIN", "URL", "Maicious_Domain(s)_IP"]

#############################################################################################

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
    print ("Sheet Names Found ----> {} " .format(sheet_name_list))
    return sheet_name_list

# extract data from first column of verified sheet names into a holding list
def extract_data(xd):
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

    holding_list_hash_count = len(holding_list_hash)
    holding_list_address_count = len(holding_list_address)

    if holding_list_hash_count > 0:
        print ("Extracted {} potential hashes from Sheets {} " .format(holding_list_hash_count, sheet_name_hashes))
    if holding_list_address_count > 0:
        print ("Extracted {} potential ip/url from Sheets {} " .format(holding_list_address_count, sheet_name_address))
    if len(sheet_name_unknown) > 0:
        print ("No data extracted from Sheet {} " .format(sheet_name_unknown))
    return [holding_list_hash_count, holding_list_address_count]

def process_data(xd):
    if xd[0] > 0:
        print ("Processing Hashes")
        for i in holding_list_hash:
            pass
            
    if xd[1] > 0:
        print ("Processing IP/URL")
        for i in holding_list_address:
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
    print ("Multiple xlsx files found, only one file can be processed, remove the rest and rerun the script")
    quit()

# If no file found, quit
if 'file_name' not in globals():
    print ("No xlsx file found")
    quit()

# Ask for password if encrypted
if isExcelEncrypted(file_name) is True:
    temp = io.BytesIO()
    with open (file_name, 'rb') as f:
        excel = msoffcrypto.OfficeFile(f)
        excel.load_key(input("{} is encrypted, enter password: " .format(file_name)))
        excel.decrypt(temp)
        file_name = temp

        sheet_names = get_sheet_names(file_name)
        holding_list_counts = extract_data(sheet_names)
        process_data(holding_list_counts)
else:
    print ("{} is not encrypted, no password required" .format(file_name))
    sheet_names = get_sheet_names(file_name)
    holding_list_counts = extract_data(sheet_names)
    process_data(holding_list_counts)






