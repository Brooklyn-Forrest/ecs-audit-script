# Dell ECS Audit Tool
# Ver 3.2
# Version notes: AD Groups implemented
# -Proxy configured
# -Code cleanup
# -Work on text to html conversion done
# -Web server components implemented
# -WDC02 IP Corrected, BRC IP added

import json
import requests
from datetime import datetime
import os
import re
import csv

del os.environ["HTTP_PROXY"]
del os.environ["HTTPS_PROXY"]

timestamp = datetime.now()
datestamp = timestamp.strftime("%m-%d-%Y")
cMonth = timestamp.strftime("%B")
cYear = timestamp.strftime("%Y")
monthNum = timestamp.strftime("%m")

prefixlocal = "Redacted"
prefixweb = "Redacted"
# CA1 ECS
fileca1 = "Redacted/ECS/Ca01_ECS01_(IP ADDRESS)/AD_Records/AD_Validation_" + datestamp + ".html"
fileca1s = "Redacted/ECS/Ca01_ECS01_(IP ADDRESS)/Service/Service_" + datestamp + ".html"
fileca1u = "Redacted/ECS/Ca01_ECS01_(IP ADDRESS)/Other_Users/Object_Users_" + datestamp + ".html"

# CA2 ECS
fileca2 = "CRedactedECS/Ca02_ECS01_(IP ADDRESS)/AD_Records/AD_Validation_" + datestamp + ".html"
fileca2s = "CRedactedECS/Ca02_ECS01_(IP ADDRESS)/Service/Service_" + datestamp + ".html"
fileca2u = "Redacted/ECS/Ca02_ECS01_(IP ADDRESS)/Other_Users/Object_Users_" + datestamp + ".html"

# BRC02 ECS
filew1 = "Redacted/ECS/BrcEcs02_(IP ADDRESS)/AD_Records/AD_Validation_" + datestamp + ".html"
filew1s = "Redacted/ECS/BrcEcs02_(IP ADDRESS)/Service/Service_" + datestamp + ".html"
filew1u = "Redacted/ECS/BrcEcs02_(IP ADDRESS)/Other_Users/Object_Users_" + datestamp + ".html"

# WDC02 ECS
filew2 = "Redacted/ECS/WdcVdc02_(IP ADDRESS)/AD_Records/AD_Validation_" + datestamp + ".html"
filew2s = "Redacted/ECS/WdcVdc02_(IP ADDRESS)/Service/Service_" + datestamp + ".html"
filew2u = "Redacted/ECS/WdcVdc02_(IP ADDRESS)/Other_Users/Object_Users_" + datestamp + ".html"

filelist = [[fileca1, fileca1s, fileca1u], [fileca2, fileca2s, fileca2u], [filew1, filew1s, filew1u], [filew2, filew2s, filew2u]]

# Clears export file if it already exists, then prepares/formats it.
for num1, files in enumerate(filelist):
    for num2, file in enumerate(files):
        with open(file, 'w') as f:

            # Sys
            if num1 == 0:
                sys = "ECS CA1_(IP ADDRESS)"
            elif num1 == 1:
                sys = "ECS CA2_(IP ADDRESS)"
            elif num1 == 2:
                sys = "ECS BRC02_(IP ADDRESS)"
            elif num1 == 3:
                sys = "ECS WDC02_(IP ADDRESS)"
            else:
                sys = "undefined"

            # Cat
            if num2 == 0:
                cat = "AD Groups"
            elif num2 == 1:
                cat = "Service Accounts"
            elif num2 == 2:
                cat = "Object Users"
            else:
                cat = "undefined"

            # Label
            f.writelines("<!DOCTYPE HTML>\n<link rel='stylesheet' href='Redacted/ECS/index.css'>\n<head>"
                         "\n<title>View HTML- ECS</title>\n</head>\n</body>\n"
                         "<h4>This file was written on " + datestamp + " and the target is: " + sys + "\t\t" + cat +
                         "</h4>\n")
            f.close()


with open("Redacted/scripts/restrict/InfoH.txt", "r") as authFile:
    username = authFile.readline()
    password = authFile.readline()
    username = username.rstrip("\n")

def retrivalProcess(filesint, title, ip):
    dateF = timestamp.strftime("%x, %X")

    currentLoginUrl = ''
    currentRequestUrl = ''

    humanadminlist = []  # AD Group(s) with root authority
    humannonadmin = []  # AD Group(s) without root authority.
    servicelist = []  # Accounts that aren't object users or human. Includes built-ins.
    objlist = []  # Object user accounts
    # Straightforward enough, right?

    params = {
        'using cookies': 'true'
    }

    currentLoginUrl = f"https://{ip}/login"
    currentRequestUrl = f"https://{ip}/vdc/users"
    fullRequestUrl = f"https://{ip}/object/users"

    global e
    try:
        response = requests.get(currentLoginUrl, params=params, verify=False,
                                auth=(username, password))  # Cookies Saved
        global headerToken
        headerToken = response.headers['X-SDS-AUTH-TOKEN']
    except requests.exceptions.RequestException as e:
        print(e)
        sv = True
        msgBox(sv)

    headers = {
        'dataType': 'json',
        'Content-Type': 'application/json',
        'accept': 'application/json',
        'X-SDS-AUTH-TOKEN': headerToken
    }
    # Format raw json data into string, then a dictionary
    requestMgmtData = (requests.get(currentRequestUrl, headers=headers, verify=False))
    str_data = requestMgmtData.content.decode('utf-8')
    dataFD = json.loads(str_data)  # Convert json to python readable finished dictionary

    # AD Groups/DTs and then finally built-ins.
    for i in dataFD['mgmt_user_info']:  # Look for data table
        if re.search('g-', str(i)):
            if i['isSystemAdmin']:
                humanadminlist.append([i['userId'], "Yes"])
            else:
                humannonadmin.append([i['userId'], "No"])
        elif re.search('[dD][tT][0-9]{6}|[dD][tT][0-9]{5}', str(i)):
            if i['isSystemAdmin']:
                humanadminlist.append([i['userId'], "Yes"])
            else:
                humannonadmin.append([i['userId'], "No"])
        else:
            if i['isSystemAdmin']:
                servicelist.append([i['userId'], "Yes"])
            else:
                servicelist.append([i['userId'], "No"])

    # Request for object user accounts
    requestObjUsers = (requests.get(fullRequestUrl, headers=headers, verify=False))
    str_data_obj = requestObjUsers.content.decode('utf-8')
    dataObjFD = json.loads(str_data_obj)

    for i in dataObjFD['blobuser']:
        if re.search('isSystemAdmin', str(i)):
            objlist.append([i['userid'], "Yes"])
        else:
            objlist.append([i['userid'], "No"])

    # Form data for python html-->pdf conversion process
    def infoappend(folder, text, currfile):
        currfile.writelines(
            '<form id="info" hidden action="converttohtml.php" method="post">'
            '<label for="url" hidden>Url</label>'
            '<input hidden id="url" name="url" '
            'value="' + prefixweb + title + "/" + folder + text + datestamp + '">'
            '<label for="path"></label>'
            '<input hidden id="path" name="path" '
            'value="' + prefixlocal + title + '/PDFS/x_on-demand/">'
            '<label for="pathalt"></label>'
            '<input hidden id="pathalt" name="pathalt" '
            'value="' + prefixweb + title + '/PDFS/x_on-demand/">'
            '</form><button onclick="info.submit()">Convert to PDF</button></html>')

    for enum, file in enumerate(filesint):
            with open(file, 'a') as internalf:
                if enum == 0:
                    internalf.write("<table><caption>" + title + "</caption><thead><tr><td>User ID</td><td>Admin Status</td></tr></thead>\n")
                    for datagroup in humanadminlist:
                        internalf.write("<tr>\n")  # Open row
                        internalf.write("<td>" + datagroup[0] + "</td>\n")  # User ID
                        internalf.write("<td>" + datagroup[1] + "<td>\n")   # Admin y/n
                        internalf.write("</tr>\n")  # Close row
                    humanadminlist.clear()
                    for datagroup2 in humannonadmin:
                        internalf.write("<tr>\n")  # Open row
                        internalf.write("<td>" + datagroup2[0] + "</td>\n")  # User ID
                        internalf.write("<td>" + datagroup2[1] + "<td>\n")  # Admin y/n
                        internalf.write("</tr>\n")  # Close row
                    humannonadmin.clear()
                    internalf.write("</table>\n")  # End table

                    infoappend("AD_Records", "/AD_Validation_", internalf)
                    internalf.close()
                elif enum == 1:
                    internalf.write("<table><caption>" + title + "</caption><thead><tr><td>Service Account ID</td><td>Admin Status</td></tr></thead>")
                    for datagroup in servicelist:
                        internalf.write("<tr>\n")  # Open row
                        internalf.write("<td>" + datagroup[0] + "</td>\n")  # Name of Account
                        internalf.write("<td>" + datagroup[1] + "<td>\n")   # Admin y/n
                        internalf.write("</tr>\n")  # Close row
                    servicelist.clear()
                    internalf.write("</table>\n")  # End table

                    infoappend("Service", "/Service_", internalf)
                    internalf.close()

                elif enum == 2:
                    internalf.write("<table><caption>" + title + "</caption><thead><tr><td>Object Username</td><td>Admin Status</td></tr></thead>")
                    for datagroup in objlist:
                        internalf.write("<tr>\n")  # Open row
                        internalf.write("<td>" + datagroup[0] + "</td>\n")  # Object Username
                        internalf.write("<td>" + datagroup[1] + "<td>\n")  # Admin y/n (this will always be No)
                        internalf.write("</tr>\n")  # Close row
                    internalf.write("</table>\n")  # End table
                    objlist.clear()
                    infoappend("Other_Users", "/ObjectUsers_", internalf)
                    internalf.close()
                else:
                    print("There are too many files in filelist!")


finished = False
while not finished:
    for titlenum, files in enumerate(filelist):
        if titlenum == 0:
            label = "Ca01_ECS01_(IP ADDRESS)"
            ipx = "(IP ADDRESS):PORT"
        elif titlenum == 1:
            label = "Ca02_ECS01_(IP ADDRESS)"
            ipx = "(IP ADDRESS):PORT"
        elif titlenum == 2:
            label = "BrcEcs02_(IP ADDRESS)"
            ipx = "(IP ADDRESS):PORT"
        elif titlenum == 3:
            label = "WdcVdc02_(IP ADDRESS)"
            ipx = "(IP ADDRESS):PORT"
        else:
            label = "undefined"
            ipx = "undefined"
        retrivalProcess(files, label, ipx)

    finished = True
