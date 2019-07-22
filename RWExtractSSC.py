from RWSSC_Utils import sscUtils
from RWSSCESutil import SSCESUtils
from RWelasticUtils import elasticUtil
import sys
import json
import os.path
import os
import logging
from configLogging import configLogging

with open('settings.json') as json_data:
    settings = json.load(json_data)

configLogging(settings)

logging.info('Starting ExtractSSC process')

ssc = sscUtils()
_url = settings['elasticURL']
es = elasticUtil(_url)
sscES = SSCESUtils()

ssc.sscAuth('F86GW27', 'DK268gatFD!')

logging.info('Getting ProjectVersions')

projectVersions = ssc.getProjectVersions()

iTotal = len(projectVersions['data'])
logging.info(iTotal)

pvCount = 0
for projectVersion in projectVersions['data']:

    pvCount = pvCount + 1
    needsReset = False
    
    logging.info(pvCount)

    projid = projectVersion['id']

    holdlastFPR = json.dumps(projectVersion['currentState']['lastFprUploadDate'])

    logging.info(projid)

    foundproject = es.searchSSCProjectsforProjectId(projid)
    #logging.info(foundproject)
    
    if foundproject['hits']['total'] == 1:
        lastFPRdate = json.dumps(foundproject['hits']['hits'][0]['_source']['currentState']['lastFprUploadDate'])
        #logging.info (lastFPRdate)

        if lastFPRdate == holdlastFPR:
            #logging.info('Found project and lastFPRUploadDate Matched')

            #match found - see if counts have changed

            issues_count = ssc.getProjectVersionIssueCounts(projid)

            #logging.info(issues_count)

            jprojcounts = json.dumps(issues_count)
            holdcritical = issues_count['critical']
            holdhigh = issues_count['high']
            holdmedium = issues_count['medium']
            holdlow = issues_count['low']
            #holdhidden = issues_count['hiddenCount']
            holdsuppressed = issues_count['suppressedCount']
            holdremoved = issues_count['removedCount']

            foundprojcounts = es.searchSSCProjectCountsforProjectId(projid)
            #logging.info(foundprojcounts)

            if foundprojcounts['hits']['total'] == 1:
                comparecritical = foundprojcounts['hits']['hits'][0]['_source']['critical']
                comparehigh = foundprojcounts['hits']['hits'][0]['_source']['high']
                comparemedium = foundprojcounts['hits']['hits'][0]['_source']['medium']
                comparelow = foundprojcounts['hits']['hits'][0]['_source']['low']
                #comparehidden = foundprojcounts['hits']['hits'][0]['_source']['hiddenCount']
                comparesuppressed = foundprojcounts['hits']['hits'][0]['_source']['suppressedCount']
                compareremoved = foundprojcounts['hits']['hits'][0]['_source']['removedCount']

                '''if ((holdcritical == comparecritical) and (holdhigh == comparehigh) and (holdmedium == comparemedium) and (holdlow == comparelow)
                     and (holdhidden == comparehidden) and (holdsuppressed == comparesuppressed) and (holdremoved == compareremoved)):'''

                if ((holdcritical == comparecritical) and (holdhigh == comparehigh) and (holdmedium == comparemedium) and (holdlow == comparelow)
                     and (holdsuppressed == comparesuppressed) and (holdremoved == compareremoved)):

                    #logging.info(projid)
                    logging.info ('found project & counts and they all match')
                    needReset = False

                else:
                    #logging.info(projid)
                    logging.info ('found counts and they are different')
                    needReset = True
            else:
                #logging.info(projid)
                logging.info('did not find counts')
                needReset = True

        else:
            #logging.info(projid)
            logging.info('found project but different lastFPRUploadDate')
            needReset = True    
    else:
        #logging.info(projid)
        logging.info('did not find project at all')
        needReset = True

    logging.info(needReset)

    if needReset == True:

        '''
        clear out  elastic tables to reset to current state for the release (projectVersionId)
        '''

        delproject = es.deleteSSCProjectsbyProjectId(projid)
        logging.info(delproject)
        delprojectc = es.deleteSSCProjectCountsbyProjectId(projid)
        logging.info(delprojectc)
        delprojecta = es.deleteSSCProjectAttrsbyProjectId(projid)
        logging.info(delprojecta)
        delprojects = es.deleteSSCProjectScansbyProjectId(projid)
        logging.info(delprojects)
        delprojecti = es.deleteSSCProjectIssuesbyProjectId(projid)
        logging.info(delprojecti)


        #post Project record (application and release)

        jproject = json.dumps(projectVersion)
        #logging.info(jproject)

        es.postSSCProjects(jproject)

        #post Project summary counts for matching
        issues_count = ssc.getProjectVersionIssueCounts(projid)

        #logging.info(issues_count)

        jprojcounts = json.dumps(issues_count)
        
        es.postSSCProjCounts(jprojcounts)

        #repost Project attributes
        projectAttrs = ssc.getProjectVersionAttributes(projid)

        #logging.info(projectAttrs)

        attCount = 0
        
        for projectAttr in projectAttrs['data']:

            attCount = attCount + 1
            #logging.info(attCount)
            #logging.info(projectAttr)

            #post Project Attribute records
            es.postSSCProjAttrs(projid, projectAttr)


        #post Project scans
        projectScans = ssc.getProjectVersionScans(projid)

        #logging.info(projectScans)

        scnCount = 0
           
        for projectScan in projectScans['data']:

            scnCount = scnCount + 1
            #logging.info(scnCount)
            #logging.info(projectScan)

            #post Project Scan records
            es.postSSCProjScans(projid, projectScan)

        #post Project issues          
        projectIssues = ssc.getAndLoadProjectVersionIssues(projid, _url)

        #logging.info(projectIssues)

        #issCount = 0
           
        #for projectIssue in projectIssues['data']:

            #issCount = issCount + 1
            #logging.info(issCount)
            #logging.info(projectIssue)

            #post Project Issue records
            #es.postSSCProjIssues(json.dumps(projectIssue))

        #logging.info('stop after first test of reload')
        #sys.exit()
    
