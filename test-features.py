from datetime import datetime
from operator import index
from openpyxl import load_workbook
import pandas as pd
import msoffcrypto, io, os, re, csv

def sanitize_ports(xd):
    new_xd = []
    for string in xd:
        check = ([(m.span()) for m in re.finditer(r"\b:[\d]{1,}\b", string)])
        if len(check) > 0:
            indexes = check[0]
            impt_index = indexes[0]
            print ("port number detected in {} at index {}" .format(string, str(impt_index)))
            new_string = string[:impt_index]
            print ("sanitised output: " + new_string)
            new_xd.append(new_string)
        else:
            new_xd.append(string)
    return new_xd

thislist = ["https://ssssuperman.com:3010/download.exe", "20.23.123.42:3000", "20.23.123.42", "20.23.123.42:a", "20.23.123.42:1a", "20.23.123.42:b1",]

print (sanitize_ports(thislist))