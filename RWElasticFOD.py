from RWFODUtils import fodUtils
from RWFODESutil import FODESUtils
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
fodES = FODESUtils()

'''fodES.getAllESFODApplications()

iFODAppCount = 0

for fodApplication in fodES._allFODApplications:
    iFODAppCount = iFODAppCount + 1

    logging.info(iFODAppCount)
    logging.info(fodApplication)

fodES.getAllESFODReleases()

iFODRelCount = 0

for fodRelease in fodES._allFODReleases:
    iFODRelCount = iFODRelCount + 1

    logging.info(iFODRelCount)
    logging.info(fodRelease)'''

'''fodES.getAllESFODCounts()

iFODCntCount = 0

for fodCount in fodES._allFODCounts:
    iFODCntCount = iFODCntCount + 1

    logging.info(iFODCntCount)
    logging.info(fodCount)'''

fodES.getAllESFODScans()

iFODScnCount = 0

for fodScan in fodES._allFODScans:
    iFODScnCount = iFODScnCount + 1

    logging.info(iFODScnCount)
    logging.info(fodScan)

fodES.getAllESFODScanSummary()

iFODScnSumCount = 0

for fodScanSum in fodES._allFODScanSummary:
    iFODScnSumCount = iFODScnSumCount + 1

    logging.info(iFODScnSumCount)
    logging.info(fodScanSum)

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

'''sscES.getAllESSSCProjIssues()

iProjIssuesCount = 0

for sscProjIssue in sscES._allSSCProjectIssues:
    iProjIssuesCount = iProjIssuesCount + 1

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

