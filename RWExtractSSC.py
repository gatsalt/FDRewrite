'''
RWExtractSCC - Extract information from SSC and populate Elastic tables - pull new information if either scandate changed or counts changed
'''

'''
Initialization and setup/configuration - includes establishing authorization
'''

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

ssc.sscAuth('F86GW27', 'DEltaFD268!')

'''
Extract latest ProjectVersion (release) information from SSC
'''

logging.info('Getting ProjectVersions')

projectVersions = ssc.getProjectVersions()

iTotal = len(projectVersions['data'])
logging.info(iTotal)

pvCount = 0

'''
For each ProjectVersion record - check to see if new information available to update elastic tables
'''

for projectVersion in projectVersions['data']:

    #increment record count and initialize indicator for whether update needed - default to no update needed
    pvCount = pvCount + 1
    needsReset = False
    
    logging.info(pvCount)

    #hold on to ProjectVersion id (release id) and latest scan date from ProjectVersion record
    projid = projectVersion['id']
    holdlastFPR = json.dumps(projectVersion['currentState']['lastFprUploadDate'])

    logging.info(projid)

    #search SSC Projects elastic table (sscprojects) for current ProjectVersion record
    foundproject = es.searchSSCProjectsforProjectId(projid)
    #logging.info(foundproject)
    
    '''
    if found - should only be one record in table
    '''

    if foundproject['hits']['total'] == 1:

        #capture latest scan date from elastic table for comparison
        lastFPRdate = json.dumps(foundproject['hits']['hits'][0]['_source']['currentState']['lastFprUploadDate'])
        #logging.info (lastFPRdate)

        #compare latest scan date from elastic table to latest scan date from current SSC record
        if lastFPRdate == holdlastFPR:
            #logging.info('Found project and lastFPRUploadDate Matched')

            #match found - see if counts have changed

            '''
            get counts (critical, high, medium, low, removed and suppressed) from current SSC for release
            '''

            issues_count = ssc.getProjectVersionIssueCounts(projid)

            #logging.info(issues_count)

            #hold returned counts for comparision to elastic table for Project Counts

            jprojcounts = json.dumps(issues_count)
            holdcritical = issues_count['critical']
            holdhigh = issues_count['high']
            holdmedium = issues_count['medium']
            holdlow = issues_count['low']
            holdsuppressed = issues_count['suppressedCount']
            holdremoved = issues_count['removedCount']

            #search elastic table of ProjectCounts for given release (projid)

            foundprojcounts = es.searchSSCProjectCountsforProjectId(projid)
            #logging.info(foundprojcounts)

            #if found - should only be one record in table

            if foundprojcounts['hits']['total'] == 1:

                #hold counts from elastic table for comparison

                comparecritical = foundprojcounts['hits']['hits'][0]['_source']['critical']
                comparehigh = foundprojcounts['hits']['hits'][0]['_source']['high']
                comparemedium = foundprojcounts['hits']['hits'][0]['_source']['medium']
                comparelow = foundprojcounts['hits']['hits'][0]['_source']['low']
                comparesuppressed = foundprojcounts['hits']['hits'][0]['_source']['suppressedCount']
                compareremoved = foundprojcounts['hits']['hits'][0]['_source']['removedCount']

                # compare counts from current release to information from elastic table for given release
                if ((holdcritical == comparecritical) and (holdhigh == comparehigh) and (holdmedium == comparemedium) and (holdlow == comparelow)
                     and (holdsuppressed == comparesuppressed) and (holdremoved == compareremoved)):

                    # if they match - no update needed (scan date and counts match between current release and elastic table)
                    #logging.info(projid)
                    logging.info ('found project & counts and they all match')
                    needReset = False

                else:
                    # if counts do not match - update needed
                    #logging.info(projid)
                    logging.info ('found counts and they are different')
                    needReset = True
            else:
                # if counts not found in table - update needed
                #logging.info(projid)
                logging.info('did not find counts')
                needReset = True

        else:
            #if last scan date is different - update needed
            #logging.info(projid)
            logging.info('found project but different lastFPRUploadDate')
            needReset = True    
    
    else:
        #if no record found in elastic table for given release - update needed
        #logging.info(projid)
        logging.info('did not find project at all')
        needReset = True

    logging.info(needReset)

    '''
    based on comparison of current record to information in elastic table an indicator is set whether an update is needed for the given release
    if the indicator is false (no update needed) - read next release record
    if the indicator is true (update needed - do update processing)

    '''

    if needReset == True:

        #update is required (either to update existing information in elastic or do initial add of information to elastic)

        '''
        clear out all five elastic tables to reset to current state for the release (projectVersionId) - may not have any records to delete if intial load for release
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


        '''
        post Project record (application and release) from current release record
        '''

        jproject = json.dumps(projectVersion)
        #logging.info(jproject)
        es.postSSCProjects(jproject)

        '''
        post Project summary counts which are held for matching
        pull information from current system - may not have been pulled in original comparison
        '''

        issues_count = ssc.getProjectVersionIssueCounts(projid)
        #logging.info(issues_count)
        jprojcounts = json.dumps(issues_count)
        es.postSSCProjCounts(jprojcounts)

        '''
        post or repost Project attributes for the given release
        '''

        projectAttrs = ssc.getProjectVersionAttributes(projid)
        #logging.info(projectAttrs)
        attCount = 0
        
        for projectAttr in projectAttrs['data']:
            attCount = attCount + 1
            #logging.info(attCount)
            #logging.info(projectAttr)
            #post Project Attribute records
            es.postSSCProjAttrs(projid, projectAttr)

        '''
        post or repost Project scan information for the given release
        '''
        
        projectScans = ssc.getProjectVersionScans(projid)
        #logging.info(projectScans)
        scnCount = 0
           
        for projectScan in projectScans['data']:
            scnCount = scnCount + 1
            #logging.info(scnCount)
            #logging.info(projectScan)
            #post Project Scan records
            es.postSSCProjScans(projid, projectScan)

        '''
        post or repost Project Issue information for the given release
        only get open, removed or suppressed issues - hidden issues are captured in a separate table if wanted 
        because there can be a large number of issues - get and post at the same time to allow for batching
        '''

        projectIssues = ssc.getAndLoadProjectVersionIssues(projid, _url)

    
