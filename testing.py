

# holding_list_address = ["1[.]2[.]3","www[.]com"]

# def remove_boxes(xd):
#         xd = list(map(str, xd))
#         # replace [.] and [:] 
#         xd1 = [w.replace("[.]", ".") for w in xd]
#         xd2 = [w.replace("[:]", ":") for w in xd1]
#         # remove any whitespaces in the list 
#         xd3 = [w.strip() for w in xd2]


# def pull_sheet_names(xd):
#         with open (xd, "r") as f:
#             reader = [w.strip() for w in f.readlines()]
#             return reader

# pull_sheet_names("sheet_hash.txt")
# pull_sheet_names("sheet_address.txt")

test = "super"
test = test.capitalize()
print (test)