'''
/* Copyright (C) Saltworks Security, LLC - All Rights Reserved
* Unauthorized copying of this file, via any medium is strictly prohibited
* Proprietary and confidential
* Written by Saltworks Security, LLC  (www.saltworks.io) , 2019
*/
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

logging.info('Starting CheckSSC Dropped Projects to Archive')

ssc = sscUtils()
_url = settings['elasticURL']
es = elasticUtil(_url)
sscES = SSCESUtils()

ssc.sscAuth('F86GW27', 'SIgmaFD268!')

logging.info('Getting ProjectVersions from SSC')

projectVersions = ssc.getProjectVersions()
iTotal = len(projectVersions['data'])
logging.info(iTotal)

logging.info('Getting ProjectVersions from Elastic SSC Projects table')

sscES.getAllESSSCProjects()
counttoarchive = 0

for sscProj in sscES._allSSCProjects:

    holdprojectID = sscProj['id']

    bfoundincurrent = False

    for projectVersion in projectVersions['data']:

        projid = projectVersion['id']

        if holdprojectID == projid:
            bfoundincurrent = True

    if bfoundincurrent == False:
        logging.info ('archive this project {}'.format(holdprojectID))
        logging.info (sscProj)
        logging.info(holdprojectID)
        jproject = json.dumps(sscProj)
        es.postSSCProjectsArchive(jproject)
        delproject = es.deleteSSCProjectsbyProjectId(holdprojectID)
        logging.info(delproject)
        counttoarchive = counttoarchive + 1
        

logging.info(counttoarchive)
    
    
    