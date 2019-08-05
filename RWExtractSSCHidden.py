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

logging.info('Starting ExtractSSCHidden process')

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

    issues_count_hidden = ssc.getProjectVersionIssueCountsHidden(projid)

    #logging.info(issues_count_hidden)

    jprojcounts = json.dumps(issues_count_hidden)
    holdhidden = issues_count_hidden['hiddenCount']
    
    foundprojcountshidden = es.searchSSCProjectCountsHiddenforProjectId(projid)
    #logging.info(foundprojcountshidden)

    if foundprojcountshidden['hits']['total'] == 1:
        comparehidden = foundprojcountshidden['hits']['hits'][0]['_source']['hiddenCount']
        
        if (holdhidden == comparehidden):
            logging.info(projid)
            logging.info ('found project hidden counts and they match')
            needReset = False

        else:
            logging.info(projid)
            logging.info ('found counts and they are different')
            needReset = True
    else:
        logging.info(projid)
        logging.info('did not find counts')
        needReset = True

    
    logging.info(needReset)

    if needReset == True:

        '''
        clear out  elastic tables to reset to current state for the release (projectVersionId)
        '''

        delprojectc = es.deleteSSCProjectCountsHiddenbyProjectId(projid)
        logging.info(delprojectc)
        delprojecti = es.deleteSSCProjectIssuesHiddenbyProjectId(projid)
        logging.info(delprojecti)

        
        #post Project summary counts for matching
        issues_count_hidden = ssc.getProjectVersionIssueCountsHidden(projid)

        #logging.info(issues_count)

        jprojcounts = json.dumps(issues_count_hidden)
        
        es.postSSCProjCountsHidden(jprojcounts)
        
        #post Project issues          
        projectIssues = ssc.getAndLoadProjectVersionIssuesHidden(projid, _url)

        #logging.info(projectIssues)

        #logging.info('stop after first test of reload')
        #sys.exit()
    
