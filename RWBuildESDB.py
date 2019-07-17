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

logging.info('Create Elastic Tables for FOD and SSC')

_url = settings['elasticURL']
es = elasticUtil(_url)

#es.mapFODApplications()

#es.mapFODCounts()

#es.mapFODScans()

#es.mapFODScanSummary()

#es.mapFODRelIssues()

'''es.mapSSCProjects()

es.mapSSCProjCounts()

es.mapSSCProjAttributes()

es.mapSSCProjScans()

es.mapSSCProjIssues()'''

