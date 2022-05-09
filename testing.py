from datetime import datetime
from operator import index
from openpyxl import load_workbook
import pandas as pd
import msoffcrypto, io, os, re, csv

holding_list_address = ["1[.]2[.]3","www[.]com"]

def remove_boxes(xd):
        xd = list(map(str, xd))
        # replace [.] and [:] 
        xd1 = [w.replace("[.]", ".") for w in xd]
        xd2 = [w.replace("[:]", ":") for w in xd1]
        # remove any whitespaces in the list 
        xd3 = [w.strip() for w in xd2]

