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

_url = settings['elasticURL']
es = elasticUtil(_url)
sscES = SSCESUtils()

'''sscES.getAllESSSCProjects()

iProjcount = 0

for sscProj in sscES._allSSCProjects:
    iProjcount = iProjcount + 1

    logging.info (iProjcount)
    logging.info (sscProj)

sscES.getAllESSSCProjCounts()

iProjCountCount = 0

for sscProjCount in sscES._allSSCProjectCounts:
    iProjCountCount = iProjCountCount + 1

    logging.info (iProjCountCount)
    logging.info (sscProjCount)'''

'''sscES.getAllESSSCProjAttrs()

iProjAttrsCount = 0

for sscProjAttrs in sscES._allSSCProjectAttrs:
    iProjAttrsCount = iProjAttrsCount + 1

    logging.info (iProjAttrsCount)
    logging.info (sscProjAttrs)'''

'''uniqueprojid = es.aggregSSCProjectIssuesforDistinctProjVersId()

logging.info (json.dumps(uniqueprojid))

listofids = json.dumps(uniqueprojid['hits']['hits']['aggregations']['distinctProjectVersionId']['buckets'])

for listid in listofids:

    logging.info(listid)'''
    
'''issueName = "Poor Error Handling: Overly Broad Throws"

foundissuename = es.searchSSCProjectIssuesforIssueName(issueName)

logging.info(foundissuename)'''

'''sscES.getAllESSSCProjIssues()

iProjIssuesCount = 0

for sscProjIssue in sscES._allSSCProjectIssues:
    iProjIssuesCount = iProjIssuesCount + 1

    if iProjIssueCount >= 6577700:

        logging.info (iProjIssuesCount)
        logging.info (sscProjIssue)'''


'''with open('{}project_versions.json'.format(settings['dataFolder']), 'w') as outfile:
    json.dump(projectVersions, outfile)


cloudScanJobs = ssc.getCloudscanJob()
with open('{}cloud_scan_jobs.json'.format(settings['dataFolder']), 'w') as outfile:
    json.dump(cloudScanJobs, outfile)'''

'''
logging.info('Getting project version issue counts')

iTotal = len(projectVersions['data'])
iCount = 0
for projectVersion in projectVersions['data']:

    iCount = iCount + 1

    projectVersionCountFile = '{}issue_count_{}.json'.format(settings['dataFolder'], projectVersion['id'])
    projectVersionLOCCountFile = '{}issue_count_{}.loc.json'.format(settings['dataFolder'], projectVersion['id'])

    if not os.path.isfile(projectVersionCountFile):

        logging.info('Getting Issues {} of {} for {}'.format(iCount, iTotal, projectVersion['project']['name']))

        try:

            issues_count = ssc.getProjectVersionIssueCounts(projectVersion['id'])

            logging.debug('Writing issue_count {}'.format(iCount))

            with open(projectVersionCountFile, 'w') as outfile:
                json.dump(issues_count, outfile)


            loc_count = ssc.getProjectVersionLOCCounts(projectVersion['id'])
            with open(projectVersionLOCCountFile, 'w') as outfile:
                json.dump(loc_count, outfile)

        except:
            logging.error('Error, skipping {}'.format(projectVersion['id']))

    else:
        logging.info('{} exists, skipping'.format(projectVersionCountFile))'''

   

'''
logging.info('Getting project version summary counts')
iTotal = len(projectVersions['data'])
iCount = 0
'''

