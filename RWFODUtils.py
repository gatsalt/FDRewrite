import requests
import json
import urllib.parse
from datetime import datetime
from datetime import timedelta
import time
import sys
import logging
from configLogging import configLogging
from RWelasticUtils import elasticUtil

with open('settings.json') as json_data:
    settings = json.load(json_data)

configLogging(settings)

class fodUtils:
    def __init__(self):

        self.maxReties = 4

        https_proxy = "https://omaproxy.1dc.com:8080"


        self.proxyDict = {
            "https": https_proxy
            }



    def FODAuth(self, inClient_id, inClient_Secret):

        self.client_id = inClient_id
        self.client_secret = inClient_Secret

        _postbody = urllib.parse.urlencode({'grant_type': 'client_credentials',
                                            'scope': 'api-tenant',
                                            'client_id': self.client_id,
                                            'client_secret': self.client_secret})

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
                    }


        response = requests.post('https://api.ams.fortify.com/oauth/token',
                                 data=_postbody, headers=_Headers, proxies=self.proxyDict)  # , proxies=proxyDict, verify=False)

        _auth = json.loads(response.text)

        try:
            self.access_token = _auth["access_token"]
        except:
            logging.info('FOD Auth failed: {}'.format(response.text))

        return _auth["access_token"]



    def getApplications(self):

        _Headers = {'Authorization': 'Bearer {}'.format(self.access_token),
                    'Accept': 'application/json'
                    }

        _url = 'https://api.ams.fortify.com/api/v3/applications'

        limit = 50
        bMore = True

        iCount = 0

        totalCount = 9999

        self.applications = {
            'status': 'OK',
            'statusCode': 200,
            'errorMessage': '',
            'items': []
        }

        try:
           while iCount < totalCount:
                _url = 'https://api.ams.fortify.com/api/v3/applications?offset={}&limit=50'.format(iCount)
                logging.info(_url)

                response = requests.get(_url, headers=_Headers, proxies=self.proxyDict)

                batchApps = json.loads(response.text)

                if totalCount == 9999:
                    totalCount = batchApps['totalCount']
                    logging.info(totalCount)

                for app in batchApps['items']:
                    self.applications['items'].append(app)
                    iCount = iCount + 1
        except:
            self.applications['status'] = "Error"
            self.applications['errorMessage'] = "Error getting applications: {}".format(response.text)

        return self.applications


    def getAllreleases(self):

        _Headers = {'Authorization': 'Bearer {}'.format(self.access_token),
                    'Accept': 'application/json'
                    }

        _url = 'https://api.ams.fortify.com/api/v3/releases'

        limit = 50
        bMore = True

        rCount = 0

        totalrCount = 9999

        self.allReleases = {
            'status': 'OK',
            'statusCode': 200,
            'errorMessage': 'OK',
            'items': []
        }


        try:

            while rCount < totalrCount:
                _url = 'https://api.ams.fortify.com/api/v3/releases?offset={}&limit=50'.format(rCount)
                logging.info(_url)

                response = requests.get(_url, headers=_Headers, proxies=self.proxyDict)

                batchAllrel = json.loads(response.text)

                if totalrCount == 9999:
                    totalrCount = batchAllrel['totalCount']

                for relapp in batchAllrel['items']:
                    self.allReleases['items'].append(relapp)
                    rCount = rCount + 1

        except:
            self.allReleases['status'] = "Error"
            self.allReleases['errorMessage'] = "Error getting all releases: {}".format(response.text)



        return self.allReleases

    def getFODVulnerability(self, releaseIdv):

        logging.info('ReleaseId: {}'.format(releaseIdv))


        _Headers = {'Authorization': 'Bearer {}'.format(self.access_token),
                    'Accept': 'application/json'
                    }

        limit = 50
        vMore = True

        vCount = 0

        totalvCount = 9999 

        self.allVulns = {
            'status': 'OK',
            'statusCode': 200,
            'errorMessage': 'OK',
            'items': []
        }
        
        try:

            while vCount < totalvCount:

                #print ('got into getVulnerability loop')

                _url = '{}/api/v3/releases/{}/vulnerabilities?offset={}&limit=50&includeFixed=false&includeSuppressed=false'.format(
                    'https://api.ams.fortify.com',
                    releaseIdv,vCount
                )
                logging.info(_url)

                response = requests.get(_url, headers=_Headers, proxies=self.proxyDict)

                batchAllVul = json.loads(response.text)

                if totalvCount == 9999:
                    totalvCount = batchAllVul['totalCount']

                for vulrel in batchAllVul['items']:
                    self.allVulns['items'].append(vulrel)
                    vCount = vCount + 1

        except:
            self.allVulns['status'] = "Error"
            self.allVulns['errorMessage'] = "Error getting all vulnerabilities: {}".format(response.text)



        return self.allVulns
 
    def getAndLoadFODVulnerability(self, releaseIdv, elasticUrl):

        logging.info('ReleaseId: {}'.format(releaseIdv))

        es = elasticUtil(elasticUrl)

        _fodvuls = {'data': [], 'count': 0}

        _Headers = {'Authorization': 'Bearer {}'.format(self.access_token),
                    'Accept': 'application/json'
                    }

        limit = 50
        vMore = True

        vCount = 0

        totalvCount = 9999 

        while vMore:

            #print ('got into getVulnerability loop')

            _url = '{}/api/v3/releases/{}/vulnerabilities?offset={}&limit=50&includeFixed=true&includeSuppressed=true'.format(
                'https://api.ams.fortify.com',
                releaseIdv,vCount
            )
            logging.info(_url)

            response = requests.get(_url, headers=_Headers, proxies=self.proxyDict)

            _fodvuls = json.loads(response.text)

            if totalvCount == 9999:
                totalvCount = _fodvuls['totalCount']
                logging.info(totalvCount)

            for vulrel in _fodvuls['items']:
                #logging.info(vulrel)
                es.postFODRelIssues(vulrel)
                vCount = vCount + 1

            if vCount >= totalvCount:
                vMore = False
    
        return True
 

    def getFODSummaryCounts(self, releaseId):

        #logging.info('ReleaseId: {}'.format(releaseId))


        _Headers = {'Authorization': 'Bearer {}'.format(self.access_token),
                    'Accept': 'application/json'
                    }

        _url = '{}/api/v3/releases/{}/vulnerabilities?offset=0&limit=1&includeFixed=true&includeSuppressed=true'.format(
            'https://api.ams.fortify.com',
            releaseId

        )

        _return = {
            'releaseId': releaseId,
            'FixedIssue': 0,
            'SuppressedIssues': 0
        }

        

        response = requests.get(_url, headers=_Headers, proxies=self.proxyDict)

        _vulsum = json.loads(response.text)

        bFound = False
        for _filter in _vulsum['filters']:
            #logging.info('Filter: {}'.format(_filter))
            if _filter['fieldName'] == 'isSuppressed':
                    for _value in _filter['fieldFilterValues']:
                        #logging.info('filedName = isSupressed, value = {}'.format(_value))
                        if _value['value'] == 'true':
                            _return['SuppressedIssues'] = _value['count']
                            bFound = True

            if _filter['fieldName'] == 'status':
                    for _value in _filter['fieldFilterValues']:
                        #logging.info('filedName = status, value = {}'.format(_value))
                        if _value['value'] == 'Fix Validated':
                            _return['FixedIssue'] = _value['count']
                            bFound = True

        if not bFound:
            logging.info("vuls: {}".format(_vulsum))
        
        return _return


    def getAllFODScans(self,releaseId):

        _Headers = {'Authorization': 'Bearer {}'.format(self.access_token),
                    'Accept': 'application/json'
                    }

        _url = 'https://api.ams.fortify.com/api/v3/releases/{}/scans'.format(releaseId)

        limit = 50
        bMore = True

        scCount = 0

        totalscCount = 9999

        self.allScans = {
            'status': 'OK',
            'statusCode': 200,
            'errorMessage': 'OK',
            'items': []
        }


        try:

            while scCount < totalscCount:
                _url = 'https://api.ams.fortify.com/api/v3/releases/{}/scans/?offset={}&limit=50'.format(releaseId, scCount)
                #logging.info(_url)

                response = requests.get(_url, headers=_Headers, proxies=self.proxyDict)

                batchAllscans = json.loads(response.text)

                if totalscCount == 9999:
                    totalscCount = batchAllscans['totalCount']

                for relscan in batchAllscans['items']:
                    self.allScans['items'].append(relscan)
                    scCount = scCount + 1

        except:
            self.allScans['status'] = "Error"
            self.allScans['errorMessage'] = "Error getting all scans: {}".format(response.text)



        return self.allScans

    def getFODScanSummary(self,scanId):

        _Headers = {'Authorization': 'Bearer {}'.format(self.access_token),
                    'Accept': 'application/json'
                    }

        _url = 'https://api.ams.fortify.com/api/v3/scans/{}/summary'.format(scanId)

        self.allScanSummary = {
            'status': 'OK',
            'statusCode': 200,
            'errorMessage': 'OK',
            'items': []
        }

      
        logging.info(_url)

        response = requests.get(_url, headers=_Headers, proxies=self.proxyDict)

        self.allScanSummary["items"] = json.loads(response.text)

        return self.allScanSummary
    

    def getFODApplicationbyApplicationId(self,applicationid):

        _Headers = {'Authorization': 'Bearer {}'.format(self.access_token),
                    'Accept': 'application/json'
                    }

        _url = 'https://api.ams.fortify.com/api/v3/applications/{}/'.format(applicationid)

        self.applicationinfo = {
            'status': 'OK',
            'statusCode': 200,
            'errorMessage': 'OK',
            'items': []
        }

      
        logging.info(_url)

        response = requests.get(_url, headers=_Headers, proxies=self.proxyDict)

        self.applicationinfo["items"] = json.loads(response.text)

        return self.applicationinfo        

    def getScans(self, releaseId):

        #print ('in getScans')

        _Headers = {'Authorization': 'Bearer {}'.format(self.access_token),
                    'Accept': 'application/json'
                    }

        _url = 'https://api.ams.fortify.com/api/v3/releases/{}/scans'.format(releaseId)

        response = requests.get(_url, headers=_Headers, proxies=self.proxyDict)

        #print (response)

        if response.status_code != 200:
            return {
                "status": 'error',
                'status_code': response.status_code,
                'response': response.reason,
                'items': []

            }

        batchScans = json.loads(response.text)
        #print (batchScans)
        #print (batchScans['totalCount'])

        self.scans = {
            'status': 'OK',
            'items': [],
            'totalCount': batchScans['totalCount']
        }

        for rel in batchScans['items']:
            self.scans['items'].append(rel)

        return self.scans

        '''
        {
      "items": [
        {
          "applicationId": 100130,
          "releaseId": 160781,
          "scanId": 320170,
          "scanTypeId": 2,
          "scanType": "Dynamic",
          "assessmentTypeId": 268,
          "analysisStatusTypeId": 2,
          "analysisStatusType": "Completed",
          "startedDateTime": "2018-03-13T00:00:00",
          "completedDateTime": "2018-03-13T00:00:00",
          "totalIssues": 12,
          "starRating": 2,
          "notes": null,
          "isFalsePositiveChallenge": false,
          "isRemediationScan": false,
          "entitlementId": 6881,
          "entitlementUnitsConsumed": 6,
          "isSubscriptionEntitlement": true,
          "pauseDetails": [],
          "cancelReason": null
        }
      ],
        "totalCount": 1
        }
        '''



    def manageError(self, postData, response):

        if response.status_code == 429:

            timeToPause = int(response.headers['X-Rate-Limit-Reset']) + 2

            logging.info("Rate limit hit, pausing: {}".format(timeToPause))
            time.sleep(timeToPause)

        elif response.status_code == 500:
            logging.info("Error 500 returned, pausing for 30 seconds for system reset.")
            logging.info(response)
            time.sleep((30))

        elif response.status_code == 400:
            # Bad Reqeust
            logging.info("Error 400, bad request.")
            logging.info(postData)
            sys.exit()

        else:
            logging.info("Unknown state, exiting")
            logging.info(response)
            sys.exit()

    def downloadFPR(self, releaseID, _dlFileName, _dlFullFileName):

        # _dlFileName = "{}-{}.fpr".format(SSCPVID, datetime.today().strftime('%Y.%m.%d'))

        dlResult = {
            'status': "OK",
            'downloadFileName': _dlFileName,
            'downloadFullFileName': _dlFullFileName,
            'error': ''
        }

        # try:

        _Headers = {'Authorization': 'Bearer {}'.format(self.access_token),
                    'Accept': 'application/octet-stream'
                    }

        _url = 'https://api.ams.fortify.com/api/v3/releases/{}/fpr?scanType=Dynamic'.format(releaseID)

        # print(_url)


        response = requests.get(_url,
                                headers=_Headers, stream=True, proxies=self.proxyDict)

        # print("Status: {}".format(response.status_code))

        if response.status_code != 200:
            dlResult = {
                'status': response.status_code,
                'downloadFileName': _dlFileName,
                'downloadFullFileName': _dlFullFileName,
                'error': 'Error with Download {}'.format(response.status_code)
            }
            return dlResult

        logging.info('Writing: {}'.format(dlResult['downloadFullFileName']))
        handle = open(dlResult['downloadFullFileName'], "wb")
        for chunk in response.iter_content(chunk_size=512):
            if chunk:  # filter out keep-alive new chunks
                handle.write(chunk)

        return dlResult


