'''
/* Copyright (C) Saltworks Security, LLC - All Rights Reserved
* Unauthorized copying of this file, via any medium is strictly prohibited
* Proprietary and confidential
* Written by Saltworks Security, LLC  (www.saltworks.io) , 2019
*/
'''
import json
import sys
import csv
import os.path
import os
import datetime
import iso8601
import logging
import requests
from ABCFODUtils import fodUtils
from ABCFODESutil import FODESUtils
from ABCSSC_Utils import sscUtils
from ABCSSCESutil import SSCESUtils
from ABCelasticUtils import elasticUtil
from configLogging import configLogging
from sscOpenVulCount import sscVulCounts
from fodOpenIssCount import fodIssCounts
from fodRemovedIssCount import fodRemIssCounts

with open('ABCsettings.json') as json_data:
    settings = json.load(json_data)

configLogging(settings)

fod = fodUtils()
fod.FODAuth(settings['client_id'], settings['client_secret'])

_url = settings['elasticURL']
es = elasticUtil(_url)
ssc = sscUtils()

ssc.sscAuth('F86GW27', 'FDKAppa268!')

def addVuls(vuls, inCount):

    loopCount = inCount
    for vul in vuls['hits']['hits']:
       
        loopCount = loopCount + 1

        sscVulns.addVul(vul)

        '''if (loopCount % 1000) == 0:

            logging.info('{}\t{}\t{}\t{}'.format(loopCount, vul['_source']['projectVersionId'],
                vul['_source']['friority'],
                vul['_source']['engineCategory']))''' 
    return loopCount

def addIsss(isss, inCount):

    loopCount = inCount
    for iss in isss['hits']['hits']:
       
        loopCount = loopCount + 1

        fodIsss.addIss(iss)

        '''if (loopCount % 1000) == 0:

            logging.info('{}\t{}\t{}\t{}'.format(loopCount, iss['_source']['releaseId'],
                iss['_source']['category'],
                iss['_source']['scantype']))''' 
    return loopCount

def addRIsss(issr, inCount):

    loopCount = inCount
    for iss in issr['hits']['hits']:
       
        loopCount = loopCount + 1

        fodRIsss.addRemIss(iss)

        '''if (loopCount % 1000) == 0:

            logging.info('{}\t{}\t{}\t{}'.format(loopCount, iss['_source']['releaseId'],
                iss['_source']['category'],
                iss['_source']['scantype']))'''
    return loopCount

def initBlankReleaseObject():

    _releaseInfo = {
        '_ApplicationID': '',
        '_ApplicationName': '',
        '_ApplicationCreatedDate': '',
        '_ApplicationDescription': '',
        '_Release': '',
        '_ReleaseID': '',
        '_ReleaseCreatedDate': '',
        '_ReleaseDescription': '',
        '_ScanCount': 0,
        '_StarRating': '',
        '_staticScanDate': '',
        '_dynamicScanDate': '',
        '_businessCriticalityType': '',
        '_ApplicationType': '',
        '_UAID': '',
        '_fodIntegration': '',
        '_buildEnvironment': '',
        '_DataSource': '',
        '_IssueCountCritical': 0,
        '_IssueCountHigh': 0,
        '_IssueCountMedium': 0,
        '_IssueCountLow': 0,
        '_IssueCountCriticalStatic': 0,
        '_IssueCountHighStatic': 0,
        '_IssueCountMediumStatic': 0,
        '_IssueCountLowStatic': 0,
        '_IssueCountCriticalDyn': 0,
        '_IssueCountHighDyn': 0,
        '_IssueCountMediumDyn': 0,
        '_IssueCountLowDyn': 0,
        '_FixedIssue': 0,
        '_SuppressedIssues': 0,
        '_StaticScanStatus': '',
        '_totalIssues': 0,
        '_Total Static Scans': 0,
        '_DynScanCount': 0,        
        'DataSource': ''
    }

    return _releaseInfo

def initReleaseObject(_DataSource):

    _releaseInfo = {
        '_ApplicationID': '',
        '_ApplicationName': '',
        '_ApplicationCreatedDate': '',
        '_ApplicationDescription': '',
        '_Release': '',
        '_ReleaseID': '',
        '_ReleaseCreatedDate': '',
        '_ReleaseDescription': '',
        '_ScanCount': 0,
        '_StarRating': '',
        '_staticScanDate': '',
        '_dynamicScanDate': '',
        '_businessCriticalityType': '',
        '_ApplicationType': '',
        '_DataSource': _DataSource,
        '_IssueCountCritical': 0,
        '_IssueCountHigh': 0,
        '_IssueCountMedium': 0,
        '_IssueCountLow': 0,
        '_IssueCountCriticalStatic': 0,
        '_IssueCountHighStatic': 0,
        '_IssueCountMediumStatic': 0,
        '_IssueCountLowStatic': 0,
        '_IssueCountCriticalDyn': 0,
        '_IssueCountHighDyn': 0,
        '_IssueCountMediumDyn': 0,
        '_IssueCountLowDyn': 0,
        '_FixedIssue': 0,
        '_SuppressedIssues': 0,
        '_StaticScanStatus': '',
        '_totalIssues': 0,
        '_Total Static Scans': 0,
        '_DynScanCount': 0,
        'DataSource': _DataSource 
        
    }

    return _releaseInfo


with open('ABCsettings.json') as json_data:
    settings = json.load(json_data)

hold_now = datetime.datetime.now()
    #print (hold_now)

hold_today = hold_now.strftime("%Y/%m/%d")

print (hold_today)

CSVfilePath = settings['CSVfilePath']

try:
    if os.path.isfile(CSVfilePath):
        os.unlink(CSVfilePath)
except Exception as e:
    logging.info(e)
    sys.exit()

dataFolder = '.\\data\\'

if not os.path.exists(dataFolder):
    os.makedirs(dataFolder)

logging.info ("starting csv process")

fodES = FODESUtils()
sscES = SSCESUtils()
es = elasticUtil(settings['elasticURL'])

if not fodES.ensureIndices():
    logging.info('All FOD tables do not exists, re-run Extractor to load tables.')
    sys.exit()

if not sscES.ensureSSCIndices():
    logging.info('All SSC tables do not exists, re-run Extractor to load tables.')
    sys.exit()


sscES.getAllESSSCProjects()
fodES.getAllESFODReleases()
fodES.getAllESFODApplications()

releasesToWrite= {'data': []}

rptsToWrite= {'data': []}

rpts2ToWrite= {'data': []}

apprelInfoData = {'data': []}

iSkipcount = 0
iAppcount = 0
iFOPCount = 0
iFODCount = 0
iProjcount = 0

_lastUAID = ''
_onereleasewritten = 1

for sscProj in sscES._allSSCProjects:
    iProjcount = iProjcount + 1

    logging.info (iProjcount)

    projid = sscProj['id']
    
    bcountsscscans = 0
    bcountsscstatic = 0
    bcountsscdynamic = 0
    lastSSCScanDateStatic = "1901-01-01T00:00:00+0000"
    lastSSCScanDateDynamic = "1901-01-01T00:00:00+0000"
    
    holdUAID = json.dumps(sscProj['project']['name'])
    holdreleaseName = json.dumps(sscProj['name'])

    remqUAID = format(holdUAID).replace('"','')
    
    sscscans = es.searchSSCProjectScansforProjectId(projid)

    if sscscans['hits']['total'] > 0:

        recsfound = sscscans['hits']['total']
        #logging.info ('records found {}'.format(recsfound))
                
        scanrecord = sscscans['hits']['hits']

        for scanrec in scanrecord:

            scandetail = scanrec['_source']
            
            if scandetail['scanrec']['lastScanDate'] != None:

                bcountsscscans = bcountsscscans + 1
                scantype = scandetail['scanrec']['_embed']['scans'][0]['type']
                scandate = scandetail['scanrec']['lastScanDate']
                
                if scantype == "WEBINSPECT":
                    bcountsscdynamic = bcountsscdynamic + 1
                    if scandate > lastSSCScanDateDynamic:
                        lastSSCScanDateDynamic = scandate
                        

                if scantype == "SCA":
                    bcountsscstatic = bcountsscstatic + 1
                    if scandate > lastSSCScanDateStatic:
                        lastSSCScanDateStatic = scandate

    #logging.info('SSC dates Static {} and Dynamic {}'.format(lastSSCScanDateStatic, lastSSCScanDateDynamic))
        
    recSource = 'SSC'

    #if _useFOP:
    if (recSource == 'SSC'):
        
        iFOPCount = iFOPCount + 1
              
        hold_version = holdreleaseName

        releaseInfo = initReleaseObject('SSC')
                
        if lastSSCScanDateStatic == "1901-01-01T00:00:00+0000":
            lastSSCScanDateStatic = ''

        if lastSSCScanDateDynamic == "1901-01-01T00:00:00+0000":
            lastSSCScanDateDynamic = ''
       

        releaseInfo['_ApplicationID'] = sscProj['project']['id']
        releaseInfo['_ApplicationName'] = sscProj['project']['name']
        releaseInfo['_ApplicationCreatedDate'] = sscProj['project']['creationDate']
        releaseInfo['_ApplicationDescription'] = sscProj['project']['description']
        releaseInfo['_Release'] = sscProj['name']
        releaseInfo['_ReleaseID'] = sscProj['id']
        releaseInfo['_ReleaseCreatedDate'] = sscProj['project']['creationDate']
        releaseInfo['_ReleaseDescription'] = sscProj['name']
        
        releaseInfo['_StarRating'] = 'Completed'
        releaseInfo['_staticScanDate'] = lastSSCScanDateStatic
        releaseInfo['_dynamicScanDate'] = lastSSCScanDateDynamic

        issues_count = ssc.getProjectVersionIssueCounts(projid)

        jprojcounts = json.dumps(issues_count)
                
        releaseInfo['_IssueCountCritical'] = issues_count['critical']
        releaseInfo['_IssueCountHigh']= issues_count['high']
        releaseInfo['_IssueCountMedium'] = issues_count['medium']
        releaseInfo['_IssueCountLow'] = issues_count['low']

        releaseInfo['_totalIssues'] = releaseInfo['_IssueCountCritical'] \
            + releaseInfo['_IssueCountHigh'] \
            + releaseInfo['_IssueCountMedium']  \
            + releaseInfo['_IssueCountLow'] \

        
        releaseInfo['_FixedIssue'] = issues_count['removedCount']
        releaseInfo['_SuppressedIssues'] = issues_count['suppressedCount']
        
        releaseInfo['_ScanCount'] = bcountsscstatic + bcountsscdynamic
        releaseInfo['_Total Static Scans'] = bcountsscstatic
        releaseInfo['_DynScanCount'] = bcountsscdynamic
        
        releasesToWrite['data'].append(releaseInfo)
    

# loop through FOD releases        

holdFODapplid = ''
for fodRelease in fodES._allFODReleases:

    holdFODapplicationName = json.dumps(fodRelease['applicationName'])
    holdFODreleaseName = json.dumps(fodRelease['releaseName'])
    
    holdFODapplid = fodRelease['applicationId']
    
    holdFODReleaseId = fodRelease['releaseId']
    holdFODApplicationId = fodRelease['applicationId']
    iFODCount = iFODCount + 1
 
    fodcountscans = 0

    releaseInfo = initReleaseObject('FOD')
    
    foundapplication = es.searchFODApplicationsforApplicationId(holdFODApplicationId)

    if foundapplication['hits']['total'] == 1:

        applrecord = foundapplication['hits']['hits']
        for applrec in applrecord:
            appldetail = applrec['_source']


    foundrelease = es.searchFODReleasesforReleaseId(holdFODReleaseId)    

    if foundrelease['hits']['total'] == 1:

        rlserecord = foundrelease['hits']['hits']

        for rlserec in rlserecord:
            rlsedetail = rlserec['_source']
            

    releaseInfo['_ApplicationID'] = appldetail['applicationId']
    releaseInfo['_ApplicationName'] = appldetail['applicationName']
    releaseInfo['_ApplicationCreatedDate'] = appldetail['applicationCreatedDate']
    releaseInfo['_ApplicationDescription'] = appldetail['applicationDescription']
    releaseInfo['_businessCriticalityType'] = appldetail['businessCriticalityType']
    releaseInfo['_ApplicationType'] = appldetail['applicationType']
    releaseInfo['_Release']= rlsedetail['releaseName']
    releaseInfo['_ReleaseID'] = rlsedetail['releaseId']
    releaseInfo['_ReleaseCreatedDate'] = rlsedetail['releaseCreatedDate']
    releaseInfo['_ReleaseDescription'] = rlsedetail['releaseDescription']
    releaseInfo['_StarRating'] = rlsedetail['rating']
    releaseInfo['_StaticScanStatus'] = rlsedetail['staticAnalysisStatusType']
    releaseInfo['_staticScanDate'] = rlsedetail['staticScanDate']
    releaseInfo['_dynamicScanDate'] = rlsedetail['dynamicScanDate']

    releaseInfo['_IssueCountCritical'] = rlsedetail['critical']
    releaseInfo['_IssueCountHigh']= rlsedetail['high']
    releaseInfo['_IssueCountMedium'] = rlsedetail['medium']
    releaseInfo['_IssueCountLow'] = rlsedetail['low']

    releaseInfo['_totalIssues'] = releaseInfo['_IssueCountCritical'] \
        + releaseInfo['_IssueCountHigh'] \
        + releaseInfo['_IssueCountMedium']  \
        + releaseInfo['_IssueCountLow'] \

    foundrelcounts = es.searchFODCountsforReleaseId(holdreleaseId)

    if foundrelcounts['hits']['total'] == 1:

        #logging.info ('found it in table')
        releaseInfo['_FixedIssue'] = foundrelcounts['hits']['hits'][0]['_source']['FixedIssue']
        releaseInfo['_SuppressedIssues'] = foundrelcounts['hits']['hits'][0]['_source']['SuppressedIssues']

    fodscans = es.searchFODScansforReleaseId(holdFODReleaseId)

    bcountfodscans = 0
    bcountfoddynamic = 0
    bcountfodstatic = 0
     

    if fodscans['hits']['total'] > 0:

        fodrecsfound = fodscans['hits']['total']
        fodscanrecord = fodscans['hits']['hits']

        for fodscanrec in fodscanrecord:

            fodscandetail = fodscanrec['_source']           
            if fodscandetail['completedDateTime'] != None:

                bcountfodscans = bcountfodscans + 1
                fodscantype = fodscandetail['scanType']

                if fodscantype == "Dynamic":
                    bcountfoddynamic = bcountfoddynamic + 1

                if fodscantype == "Static" or fodscantype == 'Open Source':
                    bcountfodstatic = bcountfodstatic + 1

    releaseInfo['_ScanCount'] = bcountfodstatic + bcountfoddynamic
    releaseInfo['_Total Static Scans'] = bcountfodstatic
    releaseInfo['_DynScanCount'] = bcountfoddynamic
        
    releasesToWrite['data'].append(releaseInfo)           


logging.info("Writing export file")
with open(CSVfilePath, 'w', newline='') as csvfile:
    fieldnames = ['Application ID', 'Application', 'Application Created Date', 'Application Description', 'Star Rating',
                  'Release', 'Release ID', 'Release Created Date', 'Release Description', 'ScanCount', 'ScanCount_Static',
                  'ScanCount_Dynamic', 'IssueCountCritical',
                  'IssueCountHigh', 'IssueCountMedium', 'IssueCountLow', 'FixedIssue', 'SuppressedIssues',
                  'StaticScanStatus', 'Last Static Scan Date',
                  'Last Dynamic Scan Date',
                  'Total Issues',
                  'Business Criticality', 'Application Type',
                  'DataSource']

    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    for releaseToWrite in releasesToWrite['data']:
        writer.writerow(
            {
                'Application ID': releaseToWrite['_ApplicationID'],
                'Application': releaseToWrite['_ApplicationName'],
                'Application Created Date': releaseToWrite['_ApplicationCreatedDate'],
                'Application Description': releaseToWrite['_ApplicationDescription'],
                'Star Rating': releaseToWrite['_StarRating'],
                'Release': releaseToWrite['_Release'],
                'Release ID': releaseToWrite['_ReleaseID'],
                'Release Created Date': releaseToWrite['_ReleaseCreatedDate'],
                'Release Description': releaseToWrite['_ReleaseDescription'],
                'ScanCount': releaseToWrite['_ScanCount'],
                'ScanCount_Static': releaseToWrite['_Total Static Scans'],
                'ScanCount_Dynamic': releaseToWrite['_DynScanCount'],
                'IssueCountCritical': releaseToWrite['_IssueCountCritical'],
                'IssueCountHigh': releaseToWrite['_IssueCountHigh'],
                'IssueCountMedium': releaseToWrite['_IssueCountMedium'],
                'IssueCountLow': releaseToWrite['_IssueCountLow'],
                'FixedIssue': releaseToWrite['_FixedIssue'],
                'SuppressedIssues': releaseToWrite['_SuppressedIssues'],
                'StaticScanStatus': releaseToWrite['_StaticScanStatus'],
                'Last Static Scan Date': releaseToWrite['_staticScanDate'],
                'Last Dynamic Scan Date': releaseToWrite['_dynamicScanDate'],
                'Total Issues': releaseToWrite['_totalIssues'],
                'Business Criticality': releaseToWrite['_businessCriticalityType'],
                'Application Type': releaseToWrite['_ApplicationType'],
                'DataSource': releaseToWrite['_DataSource']
            })

