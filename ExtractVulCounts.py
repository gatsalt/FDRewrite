import json
import sys
import csv
import os
import requests
#from sscVulCount import sscVulCount
from sscVulCount import sscVulCounts
import datetime

with open('settings.json') as json_data:
    settings = json.load(json_data)

CSVSSCAggRptfilePath = settings['CSVSSCAggRptfilePath']

try:
    if os.path.isfile(CSVSSCAggRptfilePath):
        os.unlink(CSVSSCAggRptfilePath)
except Exception as e1:
    print(e1)
    sys.exit()


iRecToReturn = 1000

sscVulns = sscVulCounts()

def initBlankReportObject():

    _reportInfo = {
        '_IssueName': '',
        '_UAID': '',
        '_ReleaseName': '',
        '_ReleaseId': 0,
        '_Status': '',
        '_Risk': '',
        '_FoundDate': '',
        '_RemovedDate': '',
        '_ScanType': '',
        '_RecCount': 0,
        '_Source': '',
        '_href': ''
        }

    return _reportInfo
       

rptsToWrite = {'data': []}


def addVuls(vuls, inCount):

    loopCount = inCount
    for vul in vuls['hits']['hits']:
       
        loopCount = loopCount + 1

        sscVulns.addVul(vul)

        if (loopCount % 100000) == 0:

            print('{}\t{}\t{}\t{}\t{}'.format(loopCount, vul['_source']['projectVersionId'],
                vul['_source']['issueName'],
                vul['_source']['engineCategory'], 
                vul['_source']['suppressed']))
    return loopCount


print("Start: {}".format(datetime.datetime.now()))

_Headers = {'Accept': 'application/json',
            'Content-Type': 'application/json'}

url = 'http://localhost:9200/sscprojissues/_search?scroll=5m'

searchData = {
    "size": iRecToReturn,
    "sort": [
        "projectVersionId" 
        ]
    
    }


response = requests.post(url, data=json.dumps(searchData), headers=_Headers)

vuls = json.loads(response.text)

_scroll_id = vuls['_scroll_id']
iTotal = vuls['hits']['total']

print('Total Recs: {}'.format(iTotal))




iCount = 0 
iCount = addVuls(vuls, iCount)

#Not loop
bKeepGoing = True 
while bKeepGoing:
    url = 'http://localhost:9200/_search/scroll'

    searchData = {
        "scroll": "5m",
        "scroll_id": _scroll_id  
        }

    response = requests.post(url, data=json.dumps(searchData), headers=_Headers)

    vuls = json.loads(response.text)
    iCount = addVuls(vuls, iCount)
    if iCount >= iTotal:
    #if iCount >= 10000:
        bKeepGoing = False

print("End: {}".format(datetime.datetime.now()))

projid = ''
holdUAID = ''
holdReleaseName = ''

for vulKey in sscVulns.sscVulns:

    vul = (sscVulns.sscVulns[vulKey])
    #print(vul)

    reportInfo = initBlankReportObject()

    #print(reportInfo)

    reportInfo['_IssueName'] = vul["issueName"]
    reportInfo['_ReleaseId'] = vul["projectVersionId"]
    reportInfo['_Status'] = vul["status"]
    reportInfo['_Risk'] = vul["friority"]  
    reportInfo['_FoundDate'] = vul["foundDate"]
    reportInfo['_RemovedDate'] = vul["removedDate"]
    reportInfo['_ScanType'] = vul["engineCategory"]
    reportInfo['_Reccount'] = vul["reccount"]
    reportInfo['_Source'] = 'FOP'

    if projid != vul["projectVersionId"]:

        projid = vul["projectVersionId"]
        #print (projid)

        foundproject = sscVulns.searchSSCProjectsforProjectId(projid)

        if foundproject['hits']['total'] == 1:
            holdUAID = json.dumps(foundproject['hits']['hits'][0]['_source']['project']['name'])
            
            if holdUAID[1:5] == 'UAID':
                stripUAID = holdUAID[1:11]
            else:    
                stripUAID = holdUAID
            #print(stripUAID)
            remqUAID = format(stripUAID).replace('"','')
            #print(remqUAID)

            holdReleaseName = json.dumps(foundproject['hits']['hits'][0]['_source']['name'])
            remqReleaseName = format(holdReleaseName).replace('"','')
            #holdhref = json.dumps(foundproject['hits']['hits'][0]['_source']['_href'])
            
            holdhref = "https://fortify.1dc.com/ssc/html/ssc/version/{}/fix/null/?filterset=a243b195-0a59-3f8b-1403-d55b7a7d78e6".format(projid)
            remqhref = format(holdhref).replace('"','')


        #print(holdReleaseName)
        #print(holdhref)

    reportInfo['_UAID'] = remqUAID
    reportInfo['_ReleaseName'] = remqReleaseName
    reportInfo['_href'] = remqhref

    rptsToWrite['data'].append(reportInfo)

    #print(reportInfo)
    

with open(CSVSSCAggRptfilePath, 'w', newline='') as csvrfile:
    rfieldnames = ['Issue Name', 'UAID', 'Release Name', 'Release Id', 'Status', 'Risk', 'FoundDate', 'RemovedDate', 'ScanType', 'RecCount', 'Source', 'Link']

    writer = csv.DictWriter(csvrfile, fieldnames=rfieldnames)
    writer.writeheader()

    for rptToWrite in rptsToWrite['data']:

        
        writer.writerow(
        {
            'Issue Name': rptToWrite['_IssueName'],
            'UAID': rptToWrite['_UAID'],
            'Release Name': rptToWrite['_ReleaseName'],
            'Release Id': rptToWrite['_ReleaseId'],
            'Status': rptToWrite['_Status'],
            'Risk': rptToWrite['_Risk'],
            'FoundDate': rptToWrite['_FoundDate'],
            'RemovedDate': rptToWrite['_RemovedDate'],
            'ScanType': rptToWrite['_ScanType'],
            'RecCount': rptToWrite['_Reccount'],
            'Source': rptToWrite['_Source'],
            'Link': rptToWrite['_href']
        })
    #for vulrec in vul:

    #    print (vulrec)

    