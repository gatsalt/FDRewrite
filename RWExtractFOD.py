import json

from RWelasticUtils import elasticUtil
from RWFODUtils import fodUtils
import sys
import logging
from configLogging import configLogging

with open('settings.json') as json_data:
    settings = json.load(json_data)

configLogging(settings)    

logging.info('Starting ExtractFOD process')

_url = settings['elasticURL']
es = elasticUtil(_url)

fod = fodUtils()
fod.FODAuth(settings['client_id'], settings['client_secret'])

fod.getAllreleases()

if fod.allReleases['status'] != 'OK':
    logging.info(fod.allReleases['errorMessage'])
    sys.exit()

FODrelCount = 0
nullvalue = ''

for fodAllrel in fod.allReleases["items"]:
    
    FODrelCount = FODrelCount + 1
    needsReset = False
    checkStaticDate = True
    checkDynamicDate = True
    checkMobileDate = True

    logging.info(FODrelCount)

    holdreleaseId = fodAllrel['releaseId']

    if fodAllrel['staticScanDate'] != None:
        holdstaticScanDate = json.dumps(fodAllrel['staticScanDate'])
        checkStaticDate = True
    else:
        holdstaticScanDate = 'null'
        checkStaticDate = False

    if fodAllrel['dynamicScanDate'] != None:
        holddynamicScanDate = json.dumps(fodAllrel['dynamicScanDate'])
        checkDynamicDate = True
    else:
        holddynamicScanDate = 'null'
        checkDynamicDate = False

    if fodAllrel['mobileScanDate'] != None:
        holdmobileScanDate = json.dumps(fodAllrel['mobileScanDate'])
        checkMobileDate = True
    else:
        holdmobileScanDate = 'null'
        checkMobileDate = False

    holdcritical = fodAllrel['critical']
    holdhigh = fodAllrel['high']
    holdmedium = fodAllrel['medium']
    holdlow = fodAllrel['low']

    logging.info(holdreleaseId)

    foundrelease = es.searchFODReleasesforReleaseId(holdreleaseId)    

    if foundrelease['hits']['total'] == 1:

        #logging.info ('found it in table')
        #logging.info (json.dumps(foundrelease))

        comparestaticScanDate = json.dumps(foundrelease['hits']['hits'][0]['_source']['staticScanDate'])
        comparedynamicScanDate = json.dumps(foundrelease['hits']['hits'][0]['_source']['dynamicScanDate'])
        comparemobileScanDate = json.dumps(foundrelease['hits']['hits'][0]['_source']['mobileScanDate'])
        comparecritical = foundrelease['hits']['hits'][0]['_source']['critical']
        comparehigh = foundrelease['hits']['hits'][0]['_source']['high']
        comparemedium = foundrelease['hits']['hits'][0]['_source']['medium']
        comparelow = foundrelease['hits']['hits'][0]['_source']['low']
        datemismatch = False

        #logging.info('compare static : {} current vs {} stored'.format(holdstaticScanDate, comparestaticScanDate))
        #logging.info('compare dynamic : {} current vs {} stored'.format(holddynamicScanDate, comparedynamicScanDate))
        #logging.info('compare mobile : {} current vs {} stored'.format(holdmobileScanDate, comparemobileScanDate))
        #logging.info('compare critical : {} current vs {} stored'.format(holdcritical, comparecritical))
        #logging.info('compare high : {} current vs {} stored'.format(holdhigh, comparehigh))
        #logging.info('compare medium : {} current vs {} stored'.format(holdmedium, comparemedium))
        #logging.info('compare low : {} current vs {} stored'.format(holdlow, comparelow))

        if checkStaticDate == True:

            if holdstaticScanDate != comparestaticScanDate:
                datemismatch = True

        if checkDynamicDate == True:

            if holddynamicScanDate != comparedynamicScanDate:
                datemismatch = True

        if checkMobileDate == True:

            if holdmobileScanDate != comparemobileScanDate:
                datemismatch = True

        if datemismatch == True:

            #logging.info ('one or more dates are off - need to reset')
            needsReset = True

        else:

            if ((holdcritical == comparecritical) and (holdhigh == comparehigh) and (holdmedium == comparemedium) and (holdlow == comparelow)):

                #logging.info ('everything matches - check fixed and suppressed')

                _summary = {'releaseId': holdreleaseId, 'FixedIssue': 0, 'SuppressedIssues': 0}

                _summary = fod.getFODSummaryCounts(holdreleaseId)

                #logging.info("summary count response: {}".format(_summary))
                holdfixed = _summary['FixedIssue']
                holdsuppressed = _summary ['SuppressedIssues']

                foundrelcounts = es.searchFODCountsforReleaseId(holdreleaseId)

                if foundrelcounts['hits']['total'] == 1:

                    #logging.info ('found it in table')
                    comparefixed = foundrelcounts['hits']['hits'][0]['_source']['FixedIssue']
                    comparesuppressed = foundrelcounts['hits']['hits'][0]['_source']['SuppressedIssues']
                    #logging.info('compare fixed : {} current vs {} stored'.format(holdfixed, comparefixed))
                    #logging.info('compare suppressed : {} current vs {} stored'.format(holdsuppressed, comparesuppressed))

                    if ((holdfixed == comparefixed) and (holdsuppressed == comparesuppressed)):

                        #logging.info('all counts match - no need to reset')
                        needsReset = False

                    else:

                        #logging.info('fixed or suppressed is off - need to reset')
                        needsReset = True

                else:

                    #logging.info('no fixed or suppressed counts found - need to reset')
                    needsReset = True

            else:

                #logging.info('something off in counts - need to reset')
                needsReset = True

    else:

        #logging.info ('not in table - need to reseet - get next release')
        needsReset = True

    #logging.info('need to reset value {}'.format(needsReset))

    if needsReset == True:

        '''
        Need to reset data for release or release info was not yet added to elastic database
        '''
        logging.info ('need to reset this : {}'.format(holdreleaseId))

        '''
        get application id for release and reset (delete any existing record and load/reload application information
        '''

        holdapplicationId = fodAllrel['applicationId']
        #logging.info(holdapplicationId)

        delapplication = es.deleteFODApplicationsbyApplicationId(holdapplicationId)
        logging.info(delapplication)

        japplinfo = fod.getFODApplicationbyApplicationId(holdapplicationId)

        logging.info(json.dumps(japplinfo))

        japp = json.dumps(japplinfo['items'])
        logging.info(japp)

        es.postFODAppls(japp)

        '''
        delete any existing release information and load/reload release information
        '''

        delrelease = es.deleteFODReleasesbyReleaseId(holdreleaseId)
        logging.info(delrelease)
        delcounts = es.deleteFODCountsbyReleaseId(holdreleaseId)
        logging.info(delcounts)
        delscans = es.deleteFODScansbyReleaseId(holdreleaseId)
        logging.info(delscans)
        delscansum = es.deleteFODScanSummarybyReleaseId(holdreleaseId)
        logging.info(delscansum)
        delrelissues = es.deleteFODRelIssuesbyReleaseId(holdreleaseId)
        logging.info(delrelissues)
        
        '''
        reload release information
        '''
        jrel = json.dumps(fodAllrel)
        es.postFODRels(jrel)

        '''
        reload summary count information - fixed and suppressed - pull again just in case not pulled in compare
        '''

        _summary = {'releaseId': holdreleaseId, 'FixedIssue': 0, 'SuppressedIssues': 0}
        _summary = fod.getFODSummaryCounts(holdreleaseId)
        es.postFODCounts(_summary)


        '''
        reload/load scan information - regular and summary
        '''

        releasescans = fod.getAllFODScans(holdreleaseId)
        #logging.info("scan response: {}".format(releasescans))
        scnCount = 0
               
        for relScan in releasescans['items']:

            scnCount = scnCount + 1
            #logging.info("{} - {}".format(relScan['scanType'], relScan['scanId']))
            #logging.info(scnCount)
            #logging.info(relScan)

            #post Release Scan records
            
            es.postFODScans(relScan)

            if relScan['scanType'] != "OpenSource":

                holdscan = relScan['scanId']
                #logging.info(holdscan)
                scansumm = fod.getFODScanSummary(holdscan)
                #logging.info(scansumm)
                holdscansum = scansumm['items']
                #logging.info(holdscansum)
                es.postFODScanSummary(holdscansum)
            

        #logging.info('Getting scans succeeded')

        '''
        reload/load issues / vulnerabilities
        '''

        releaseIssues = fod.getAndLoadFODVulnerability(holdreleaseId, _url)

        #sys.exit()









    

'''fod.getApplications()

if fod.applications['status'] != 'OK':
    logging.info(fod.applications['errorMessage'])
    sys.exit()

japp = '{"applicationId": 1, "applicationName": "testrecord", "attributes": [{"name": "UAID", "id": 6907, "value": "testing"}]}'

es.postFODAppls(japp)

for fodApp in fod.applications["items"]:
    japp = json.dumps(fodApp)
    logging.info(japp)

    es.postFODAppls(japp)


logging.info('Getting applications succeeded')
for fodAllrel in fod.allReleases["items"]:
    jrel = json.dumps(fodAllrel)
    es.postFODRels(jrel)

logging.info('Getting releases succeeded, moving to summaries')

iCount = 0
iTotal = len(fod.allReleases['items'])

for fodAllrel in fod.allReleases["items"]:
    try:
        iCount = iCount + 1
        _releaseId = fodAllrel['releaseId']

        logging.info("{} of {} - {}".format(iCount, iTotal, _releaseId))

        _summary = {'releaseId': _releaseId, 'FixedIssue': 0, 'SuppressedIssues': 0}

        if ((fodAllrel['staticScanDate'] != None) or (fodAllrel['dynamicScanDate'] != None)):


            _summary = fod.getFODSummaryCounts(_releaseId)
            logging.info("summary count response: {}".format(_summary))
          

        es.postFODCounts(_summary)
    except:
        logging.info("Error getting FOD Summary Information: {}".format(_summary['errorMessage']))
        sys.exit()


logging.info('Getting getsummary count succeeded')

releasescans = fod.getAllFODScans(_releaseId)

    #logging.info("scan response: {}".format(releasescans))

    scnCount = 0
           
    for relScan in releasescans['items']:

        scnCount = scnCount + 1
        logging.info("{} - {}".format(relScan['scanType'], relScan['scanId']))
        #logging.info(scnCount)
        logging.info(relScan)

        #post Release Scan records
        
        es.postFODScans(relScan)

        if relScan['scanType'] != "OpenSource":

            holdscan = relScan['scanId']

            logging.info(holdscan)

            scansumm = fod.getFODScanSummary(holdscan)

            #logging.info(scansumm)

            holdscansum = scansumm['items']

            #logging.info(holdscansum)

            es.postFODScanSummary(holdscansum)
        

logging.info('Getting scans succeeded')'''

'''relCount = 0
relTotal = len(fod.allReleases['items'])

for fodAllrel in fod.allReleases["items"]:
    
    relCount = relCount + 1
    _releaseId = fodAllrel['releaseId']

    logging.info("{} of {} - {}".format(relCount, relTotal, _releaseId))


    releaseIssues = fod.getAndLoadFODVulnerability(_releaseId, _url)'''