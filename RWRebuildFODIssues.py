import json

from RWelasticUtils import elasticUtil
from RWFODUtils import fodUtils
import sys
import logging
from configLogging import configLogging

with open('settings.json') as json_data:
    settings = json.load(json_data)

configLogging(settings)    

logging.info('Starting rebuildFODIssues process')

_url = settings['elasticURL']
es = elasticUtil(_url)

fod = fodUtils()
fod.FODAuth(settings['client_id'], settings['client_secret'])

holdreleaseId = 141539


delrelissues = es.deleteFODRelIssuesbyReleaseId(holdreleaseId)
logging.info(delrelissues)

releaseIssues = fod.getAndLoadFODVulnerability(holdreleaseId, _url)

