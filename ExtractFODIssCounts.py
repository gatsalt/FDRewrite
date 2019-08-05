import json
import sys
import csv
import os
import requests

from fodIssCount import fodIssCounts
import datetime

with open('settings.json') as json_data:
    settings = json.load(json_data)

CSVFODAggRptfilePath = settings['CSVFODAggRptfilePath']

try:
    if os.path.isfile(CSVFODAggRptfilePath):
        os.unlink(CSVFODAggRptfilePath)
except Exception as e1:
    print(e1)
    sys.exit()


iRecToReturn = 1000

fodIsss = fodIssCounts()

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


def addIsss(isss, inCount):

    loopCount = inCount
    for iss in isss['hits']['hits']:
       
        loopCount = loopCount + 1

        fodIsss.addIss(iss)

        if (loopCount % 1000) == 0:

            print('{}\t{}\t{}\t{}\t{}'.format(loopCount, iss['_source']['releaseId'],
                iss['_source']['category'],
                iss['_source']['scantype'], 
                iss['_source']['isSuppressed']))
    return loopCount


print("Start: {}".format(datetime.datetime.now()))

_Headers = {'Accept': 'application/json',
            'Content-Type': 'application/json'}

url = 'http://localhost:9200/fodrelissues/_search?scroll=5m'

searchData = {
    "size": iRecToReturn,
    "sort": [
        "releaseId" 
        ]
    
    }


response = requests.post(url, data=json.dumps(searchData), headers=_Headers)

isss = json.loads(response.text)

_scroll_id = isss['_scroll_id']
iTotal = isss['hits']['total']

print('Total Recs: {}'.format(iTotal))




iCount = 0 
iCount = addIsss(isss, iCount)

#Not loop
bKeepGoing = True 
while bKeepGoing:
    url = 'http://localhost:9200/_search/scroll'

    searchData = {
        "scroll": "5m",
        "scroll_id": _scroll_id  
        }

    response = requests.post(url, data=json.dumps(searchData), headers=_Headers)

    isss = json.loads(response.text)
    iCount = addIsss(isss, iCount)
    if iCount >= iTotal:
    #if iCount >= 10000:
        bKeepGoing = False

print("End: {}".format(datetime.datetime.now()))

relid = ''
holdUAID = ''
holdReleaseName = ''

for issKey in fodIsss.fodIsss:

    iss = (fodIsss.fodIsss[issKey])
    #print(iss)

    reportInfo = initBlankReportObject()

    #print(reportInfo)

    reportInfo['_IssueName'] = iss["category"]
    reportInfo['_ReleaseId'] = iss["releaseId"]
    reportInfo['_Status'] = iss["status"]
    reportInfo['_Risk'] = iss["severityString"]  
    reportInfo['_FoundDate'] = iss["introducedDate"]
    reportInfo['_RemovedDate'] = iss["removedDate"]
    reportInfo['_ScanType'] = iss["scantype"]
    reportInfo['_Reccount'] = iss["reccount"]
    reportInfo['_Source'] = 'FOD'

    if relid != iss["releaseId"]:

        relid = iss["releaseId"]
        print (relid)

        foundrelease = fodIsss.searchFODReleasesforReleaseId(relid)

        #print(foundrelease)

        if foundrelease['hits']['total'] == 1:
            holdUAID = json.dumps(foundrelease['hits']['hits'][0]['_source']['applicationName'])
            
            if holdUAID[1:5] == 'UAID':
                stripUAID = holdUAID[1:11]
            else:    
                stripUAID = holdUAID
            
            #print(stripUAID)
            remqUAID = format(stripUAID).replace('"','')
            #print(remqUAID)

            holdReleaseName = json.dumps(foundrelease['hits']['hits'][0]['_source']['releaseName'])
            remqReleaseName = format(holdReleaseName).replace('"','')
            #holdhref = json.dumps(foundproject['hits']['hits'][0]['_source']['_href'])
            
            holdhref = "https://ams.fortify.com/Releases/{}/Overview".format(relid)
            remqhref = format(holdhref).replace('"','')


        #print(holdReleaseName)
        #print(holdhref)

    reportInfo['_UAID'] = remqUAID
    reportInfo['_ReleaseName'] = remqReleaseName
    reportInfo['_href'] = remqhref

    rptsToWrite['data'].append(reportInfo)

    #print(reportInfo)
    

with open(CSVFODAggRptfilePath, 'w', newline='') as csvrfile:
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
    
    