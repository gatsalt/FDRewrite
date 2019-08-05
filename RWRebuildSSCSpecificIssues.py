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

projid = 301323
issueId = 3889059


#issues = es.searchSSCProjectIssuesforProjectId(projid)

#logging.info(issues)

founddid = es.searchSSCProjectIssuesforProjectIdandIssueId(projid,issueId)

logging.info(founddid)

delresult = es.deleteSSCProjectIssuesbyProjectIdandIssueId(projid,issueId)

logging.info(delresult)

detail = ssc.getProjectVersionIssueDetail(projid,issueId)

logging.info(detail)

issdetail = detail["data"]

logging.info(issdetail)

es.postSSCProjIssues(json.dumps(issdetail))