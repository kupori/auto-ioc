# auto-ioc 

takes in a xlsx files containing IOCs (url/ip/hashes) and churns out comma delimited csv(s) for each unique ioc type

**issues:**

* if there is a typo in the Sheet name, will not be processed
  * todo: add string % based matching (eg. If name match > 80%, process the sheet)
* does not process sheetnames that are not in the lists of sheetnames
  * change sheetname input to txt file based (sheet_hash / sheet_address)
    * add the sheetname into the txt files

**long term todo:**

* esm api support
* more fields (source, campaign name, cve etc)
