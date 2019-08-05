from RWSSC_Utils import sscUtils
from RWSSCESutil import SSCESUtils
from RWelasticUtils import elasticUtil
import sys
import json
import requests
import os.path
import os
import logging
from configLogging import configLogging
from sscRemovedVulCount import sscVulCounts

with open('settings.json') as json_data:
    settings = json.load(json_data)

configLogging(settings)

logging.info('Starting Removed Date Cleanup process')

ssc = sscUtils()
_url = settings['elasticURL']
es = elasticUtil(_url)
sscES = SSCESUtils()

ssc.sscAuth('F86GW27', 'DK268gatFD!')

def addVuls(vuls, inCount):

    loopCount = inCount
    for vul in vuls['hits']['hits']:
       
        loopCount = loopCount + 1

        sscVulns.addVul(vul)

        if (loopCount % 10000) == 0:

            logging.info('{}\t{}\t{}'.format(loopCount, vul['_source']['projectVersionId'],
                vul['_source']['id']))
                
    return loopCount

sscVulns = sscVulCounts()

vuls = es.searchSSCProjectIssuesforRemovedBadDate()

_scroll_id = vuls['_scroll_id']
iTotal = vuls['hits']['total']

logging.info(iTotal)

iCount = 0 
iCount = addVuls(vuls, iCount)

#check looping
bKeepGoing = True 
while bKeepGoing:
    url = 'http://localhost:9200/_search/scroll'

    _Headers = {'Accept': 'application/json',
                'Content-Type': 'application/json'}

    searchData = {
        "scroll": "5m",
        "scroll_id": _scroll_id  
        }

    response = requests.post(url, data=json.dumps(searchData), headers=_Headers)

    vuls = json.loads(response.text)
    iCount = addVuls(vuls, iCount)
    if iCount >= iTotal:
    #if iCount >= 2000:
        bKeepGoing = False


resetcount = 0
pvicount = 0
holdprojVersionId = 0

for vulKey in sscVulns.sscVulns:

	vul = (sscVulns.sscVulns[vulKey])

	projid = vul['projectVersionId']
	issueId = vul['id']

	logging.info('pvi {} and issue {}'.format(projid,issueId))
	founddid = es.searchSSCProjectIssuesforProjectIdandIssueId(projid,issueId)
	#logging.info(founddid)
	delresult = es.deleteSSCProjectIssuesbyProjectIdandIssueId(projid,issueId)
	#logging.info(delresult)
	detail = ssc.getProjectVersionIssueDetail(projid,issueId)
	#logging.info(detail)
	issdetail = detail["data"]
	#logging.info(issdetail)
	es.postSSCProjIssues(json.dumps(issdetail))

	#logging.info(vul)

	if vul['projectVersionId'] != holdprojVersionId:
		logging.info ('release {} and count {}'.format(holdprojVersionId, pvicount))
		holdprojVersionId = vul['projectVersionId']
		pvicount = 0

	pvicount = pvicount + 1
	resetcount = resetcount + 1

logging.info ('last release {} and count {}'.format(holdprojVersionId, pvicount))
logging.info('total reset {}'.format(resetcount))



    

'''founddid = es.searchSSCProjectIssuesforProjectIdandIssueId(projid,issueId)

logging.info(founddid)

delresult = es.deleteSSCProjectIssuesbyProjectIdandIssueId(projid,issueId)

logging.info(delresult)

detail = ssc.getProjectVersionIssueDetail(projid,issueId)

logging.info(detail)

issdetail = detail["data"]

logging.info(issdetail)

es.postSSCProjIssues(json.dumps(issdetail))'''