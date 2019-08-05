'''
 
Copyright (c) Saltworks Security, LLC (2018). All rights reserved.  

FileName:

Description:

'''
import requests
import json
import logging
from configLogging import configLogging

with open('settings.json') as json_data:
    settings = json.load(json_data)

configLogging(settings)

class FODESUtils:

    def __init__(self):

        self._elasticUrl = "http://localhost:9200"
        self._allFODReleases = []
        self._allFODApplications = []
        self._allFODCounts = []
        self._allFODScans = []
        self._allFODScanSummary = []

        self._Headers = {'Accept': 'application/json',
                    'Content-Type':'application/json'
                    }


    def ensureIndices(self):

        _Headers = {'Accept': 'application/json',
                    'Content-Type':'application/json'
                    }

        logging.info('in ensureIndices')



        _url = ("{}/_cat/indices".format(self._elasticUrl))

        response = requests.get(_url, headers=_Headers)
        indices = json.loads(response.text)

        fodAppicationsExists = False
        fodReleasesExists = False
        fodAllExists = True

        for _idx in indices:

            if _idx['index'] == 'fodapplicationss':
                fodApplicationsExists = True
            elif _idx['index'] == 'fodreleases':
                fodReleasesExists = True


        if not fodApplicationsExists:
            logging.info('fodapplications does not exists')
            fodAllExists = False

        if not fodReleasesExists:
            logging.info('fodreleases does not exists')
            fodAllExists = False

        return fodAllExists



    def getAllESFODApplications(self):



        #print ('in getAllESFODrel3')

        _url = '{}/fodapplications/_search?scroll=1m'.format(self._elasticUrl)
        logging.info(_url)

        _searchPost = {
            "size": 1000,
        }

        response = requests.post(_url, data=json.dumps(_searchPost), headers=self._Headers)

        oESResponse = json.loads(response.text)

        iTotalCount = oESResponse['hits']['total']
        logging.info("Total FOD Applications in ES: {}".format(iTotalCount))

        iCount = 0
        #while iCount < iTotalCount:
        while len(oESResponse['hits']['hits']) > 0:
            for oFodApp in oESResponse['hits']['hits']:
                iCount = iCount + 1
                self._allFODApplications.append(oFodApp['_source'])

            #get the next batch
            _url = '{}/_search/scroll'.format(self._elasticUrl)
            _searchPost = {
                "scroll": "1m",
                "scroll_id": oESResponse['_scroll_id'],
            }

            response = requests.post(_url, data=json.dumps(_searchPost), headers=self._Headers)

            oESResponse = json.loads(response.text)


    def getAllESFODReleases(self):

        _Headers = {'Accept': 'application/json',
                    'Content-Type':'application/json'
                    }

        _url = '{}/fodreleases/_search?scroll=1m'.format(self._elasticUrl)
        logging.info(_url)

        _searchPost = {
            "size": 1000,
        }

        response = requests.post(_url, data=json.dumps(_searchPost), headers=_Headers)

        oESResponse = json.loads(response.text)

        iTotalCount = oESResponse['hits']['total']
        logging.info("Total FOD Releases in ES: {}".format(iTotalCount))

        iCount = 0
        #while iCount < iTotalCount:
        while len(oESResponse['hits']['hits']) > 0:
            for oFodRel in oESResponse['hits']['hits']:
                iCount = iCount + 1
                self._allFODReleases.append(oFodRel['_source'])

            #get the next batch
            _url = '{}/_search/scroll'.format(self._elasticUrl)
            _searchPost = {
                "scroll": "1m",
                "scroll_id": oESResponse['_scroll_id'],
            }

            #print(json.dumps(_searchPost))

            response = requests.post(_url, data=json.dumps(_searchPost), headers=_Headers)

            oESResponse = json.loads(response.text)
            #print(response.text)

            #print(iCount)

    def getAllESFODCounts(self):

        _Headers = {'Accept': 'application/json',
                    'Content-Type':'application/json'
                    }

        _url = '{}/fodcounts/_search?scroll=1m'.format(self._elasticUrl)
        logging.info(_url)

        _searchPost = {
            "size": 1000,
        }

        response = requests.post(_url, data=json.dumps(_searchPost), headers=_Headers)

        oESResponse = json.loads(response.text)

        iTotalCount = oESResponse['hits']['total']
        logging.info("Total FOD Counts in ES: {}".format(iTotalCount))

        cCount = 0
        #while iCount < iTotalCount:
        while len(oESResponse['hits']['hits']) > 0:
            for oFodCounts in oESResponse['hits']['hits']:
                cCount = cCount + 1
                self._allFODCounts.append(oFodCounts['_source'])

            #get the next batch
            _url = '{}/_search/scroll'.format(self._elasticUrl)
            _searchPost = {
                "scroll": "1m",
                "scroll_id": oESResponse['_scroll_id'],
            }

            #print(json.dumps(_searchPost))

            response = requests.post(_url, data=json.dumps(_searchPost), headers=_Headers)

            oESResponse = json.loads(response.text)


    def getAllESFODScans(self):

        _Headers = {'Accept': 'application/json',
                    'Content-Type':'application/json'
                    }

        _url = '{}/fodscans/_search?scroll=1m'.format(self._elasticUrl)
        logging.info(_url)

        _searchPost = {
            "size": 1000,
        }

        response = requests.post(_url, data=json.dumps(_searchPost), headers=_Headers)

        oESResponse = json.loads(response.text)

        sTotalCount = oESResponse['hits']['total']
        logging.info("Total FOD Scans in ES: {}".format(sTotalCount))

        sCount = 0
        #while iCount < iTotalCount:
        while len(oESResponse['hits']['hits']) > 0:
            for oFodScn in oESResponse['hits']['hits']:
                sCount = sCount + 1
                self._allFODScans.append(oFodScn['_source'])

            #get the next batch
            _url = '{}/_search/scroll'.format(self._elasticUrl)
            _searchPost = {
                "scroll": "1m",
                "scroll_id": oESResponse['_scroll_id'],
            }

            #print(json.dumps(_searchPost))

            response = requests.post(_url, data=json.dumps(_searchPost), headers=_Headers)

            oESResponse = json.loads(response.text)
            #print(response.text)

            #print(iCount)

    def getAllESFODScanSummary(self):

        _Headers = {'Accept': 'application/json',
                    'Content-Type':'application/json'
                    }

        _url = '{}/fodscansummary/_search?scroll=1m'.format(self._elasticUrl)
        logging.info(_url)

        _searchPost = {
            "size": 1000,
        }

        response = requests.post(_url, data=json.dumps(_searchPost), headers=_Headers)

        oESResponse = json.loads(response.text)

        ssTotalCount = oESResponse['hits']['total']
        logging.info("Total FOD Scan Summary in ES: {}".format(ssTotalCount))

        ssCount = 0
        #while iCount < iTotalCount:
        while len(oESResponse['hits']['hits']) > 0:
            for oFodScnSum in oESResponse['hits']['hits']:
                ssCount = ssCount + 1
                self._allFODScanSummary.append(oFodScnSum['_source'])

            #get the next batch
            _url = '{}/_search/scroll'.format(self._elasticUrl)
            _searchPost = {
                "scroll": "1m",
                "scroll_id": oESResponse['_scroll_id'],
            }

            #print(json.dumps(_searchPost))

            response = requests.post(_url, data=json.dumps(_searchPost), headers=_Headers)

            oESResponse = json.loads(response.text)
            #print(response.text)

            #print(iCount)

    def getAttributeFromFODApp(self, fodApp, attrName):

        for attr in fodApp['attributes']:
            if attr['name'] == attrName:
                return attr['value']

        return ''

    def getfod_vulnerability(self, releaseId):

        _url = '{}/fod_vulnerabilities/fod_vulnerabilities/{}'.format(self._elasticUrl, releaseId)

        response = requests.get(_url, headers=self._Headers)

        _vulnerability  = json.loads(response.text)

        return _vulnerability

