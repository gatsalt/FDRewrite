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


projid = 32769


delprojecti = es.deleteSSCProjectIssuesbyProjectId(projid)
logging.info(delprojecti)
logging.info(projid)

#post Project issues          
projectIssues = ssc.getAndLoadProjectVersionIssues(projid, _url)

