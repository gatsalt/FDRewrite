'''
/* Copyright (C) Saltworks Security, LLC - All Rights Reserved
* Unauthorized copying of this file, via any medium is strictly prohibited
* Proprietary and confidential
* Written by Saltworks Security, LLC  (www.saltworks.io) , 2019
*/
'''
import requests
import json
import logging
from configLogging import configLogging

with open('settings.json') as json_data:
    settings = json.load(json_data)

configLogging(settings)

class SSCESUtils:

    def __init__(self):

        self._elasticUrl = "http://localhost:9200"
        self._allSSCProjects = []
        self._allSSCProjectCounts = []
        self._allSSCProjectAttrs = []
        self._allSSCProjectAttr2 = []
        self._allSSCProjectScans = []
        self._allSSCProjectIssues = []
        self._allTestProjects = []
        self._allARIRRecords = []
        

        self._Headers = {'Accept': 'application/json',
                    'Content-Type':'application/json'
                    }


    def ensureSSCIndices(self):

        _Headers = {'Accept': 'application/json',
                    'Content-Type':'application/json'
                    }

        logging.info('in ensureSSCIndices')

        _url = ("{}/_cat/indices".format(self._elasticUrl))

        response = requests.get(_url, headers=_Headers)
        indices = json.loads(response.text)

        sscProjectsExists = False
        sscProjCountsExists = False
        sscProjAttrsExists = False
        sscProjAttr2Exists = False
        sscProjScansExists = False
        sscProjIssuesExists = False
        sscProjIssuesHiddenExists = False
        sscAllExists = True
        

        for _idx in indices:

            if _idx['index'] == 'sscprojects':
                sscProjectsExists = True
            elif _idx['index'] == 'sscprojcounts':
                sscProjCountsExists = True
            elif _idx['index'] == 'sscprojattrs':
                sscProjAttrsExists = True
            elif _idx['index'] == 'sscprojattr2':
                sscProjAttr2Exists = True
            elif _idx['index'] == 'sscprojscans':
                sscProjScansExists = True
            elif _idx['index'] == 'sscprojissues':
                sscProjIssuesExists = True
            elif _idx['index'] == 'sscprojissueshidden':
                sscProjIssuesHiddenExists = True
                
            

        if not sscProjectsExists:
            logging.info('sscProjects does not exists')
            sscAllExists = False

        if not sscProjCountsExists:
           logging.info('sscProjCounts does not exists')
           sscAllExists = False

        if not sscProjAttrsExists:
            logging.info('sscProjAttrs does not exists')
            sscAllExists = False

        if not sscProjAttr2Exists:
            logging.info('sscProjAttr2 does not exists')
            sscAllExists = False

        if not sscProjScansExists:
           logging.info('sscProjScans does not exists')
           sscAllExists = False    
            
        if not sscProjIssuesExists:
            logging.info('sscProjIssues does not exists')
            sscAllExists = False

        if not sscProjIssuesHiddenExists:
           logging.info('sscProjIssuesHidden does not exists')
           sscAllExists = False    

        return sscAllExists

    def getAllESSSCProjects(self):

        _url = '{}/sscprojects/sscprojects/_search?scroll=1m'.format(self._elasticUrl)
        logging.info(_url)

        _searchPost = {
            "size": 5000,
            "sort": [
                        {
                        "id" : {
                            "nested" : {
                                "path" : "project"
                                        }
                                }
                        }                        
                        ],
        }

        response = requests.get(_url, data=json.dumps(_searchPost), headers=self._Headers)

        oESResponse = json.loads(response.text)

        iTotalSSCCount = oESResponse['hits']['total']
        logging.info("Total SSC Projects in ES: {}".format(iTotalSSCCount))

        iCount = 0
        #while iCount < iTotalCount:
        while len(oESResponse['hits']['hits']) > 0:
            for oSscProj in oESResponse['hits']['hits']:
                iCount = iCount + 1
                #logging.info(iCount)
                self._allSSCProjects.append(oSscProj['_source'])

            #get the next batch
            _url = '{}/_search/scroll'.format(self._elasticUrl)
            _searchPost = {
                "scroll": "1m",
                "scroll_id": oESResponse['_scroll_id'],
            }

            response = requests.get(_url, data=json.dumps(_searchPost), headers=self._Headers)

            oESResponse = json.loads(response.text)

    def getAllESSSCProjCounts(self):

        _url = '{}/sscprojcounts/sscprojcounts/_search?scroll=1m'.format(self._elasticUrl)
        logging.info(_url)

        _searchPost = {
            "size": 1000,
        }

        response = requests.get(_url, data=json.dumps(_searchPost), headers=self._Headers)

        oESResponse = json.loads(response.text)

        iTotalSSCProjCount = oESResponse['hits']['total']
        logging.info("Total SSC Project Counts in ES: {}".format(iTotalSSCProjCount))

        iCount2 = 0
        #while iCount < iTotalCount:
        while len(oESResponse['hits']['hits']) > 0:
            for oSscProjCount in oESResponse['hits']['hits']:
                iCount2 = iCount2 + 1
                logging.info(iCount2)
                self._allSSCProjectCounts.append(oSscProjCount['_source'])

            #get the next batch
            _url = '{}/_search/scroll'.format(self._elasticUrl)
            _searchPost = {
                "scroll": "1m",
                "scroll_id": oESResponse['_scroll_id'],
            }

            response = requests.get(_url, data=json.dumps(_searchPost), headers=self._Headers)

            oESResponse = json.loads(response.text)

    def getAllESSSCProjAttrs(self):

        _url = '{}/sscprojattrs/sscprojattrs/_search?scroll=1m'.format(self._elasticUrl)
        logging.info(_url)

        _searchPost = {
            "size": 1000,
        }

        response = requests.get(_url, data=json.dumps(_searchPost), headers=self._Headers)

        oESResponse = json.loads(response.text)

        iTotalSSCProjAttrsCount = oESResponse['hits']['total']
        logging.info("Total SSC Project Attributes in ES: {}".format(iTotalSSCProjAttrsCount))

        iCount3 = 0
        #while iCount < iTotalCount:
        while len(oESResponse['hits']['hits']) > 0:
            for oSscProjAttrs in oESResponse['hits']['hits']:
                iCount3 = iCount3 + 1
                #logging.info(iCount3)
                self._allSSCProjectAttrs.append(oSscProjAttrs['_source'])

            #get the next batch
            _url = '{}/_search/scroll'.format(self._elasticUrl)
            _searchPost = {
                "scroll": "1m",
                "scroll_id": oESResponse['_scroll_id'],
            }

            response = requests.get(_url, data=json.dumps(_searchPost), headers=self._Headers)

            oESResponse = json.loads(response.text)

    def getAllESSSCProjAttr2(self):

        _url = '{}/sscprojattr2/sscprojattr2/_search?scroll=1m'.format(self._elasticUrl)
        logging.info(_url)

        _searchPost = {
            "size": 1000,
        }

        response = requests.get(_url, data=json.dumps(_searchPost), headers=self._Headers)

        oESResponse = json.loads(response.text)

        iTotalSSCProjAttr2Count = oESResponse['hits']['total']
        logging.info("Total SSC Project Attribute2 in ES: {}".format(iTotalSSCProjAttr2Count))

        iCount3a = 0
        #while iCount < iTotalCount:
        while len(oESResponse['hits']['hits']) > 0:
            for oSscProjAttr2 in oESResponse['hits']['hits']:
                iCount3a = iCount3a + 1
                #logging.info(iCount3)
                self._allSSCProjectAttr2.append(oSscProjAttr2['_source'])

            #get the next batch
            _url = '{}/_search/scroll'.format(self._elasticUrl)
            _searchPost = {
                "scroll": "1m",
                "scroll_id": oESResponse['_scroll_id'],
            }

            response = requests.get(_url, data=json.dumps(_searchPost), headers=self._Headers)

            oESResponse = json.loads(response.text)

    def getAllESSSCProjScans(self):

        _url = '{}/sscprojscans/sscprojscans/_search?scroll=1m'.format(self._elasticUrl)
        logging.info(_url)

        _searchPost = {
            "size": 1000,
        }

        response = requests.get(_url, data=json.dumps(_searchPost), headers=self._Headers)

        oESResponse = json.loads(response.text)

        iTotalSSCProjScansCount = oESResponse['hits']['total']
        logging.info("Total SSC Project Scans in ES: {}".format(iTotalSSCProjScansCount))

        iCountsc = 0
        #while iCount < iTotalCount:
        while len(oESResponse['hits']['hits']) > 0:
            for oSscProjScans in oESResponse['hits']['hits']:
                iCountsc = iCountsc + 1
                #logging.info(iCountsc)
                self._allSSCProjectScans.append(oSscProjScans['_source'])

            #get the next batch
            _url = '{}/_search/scroll'.format(self._elasticUrl)
            _searchPost = {
                "scroll": "1m",
                "scroll_id": oESResponse['_scroll_id'],
            }

            response = requests.get(_url, data=json.dumps(_searchPost), headers=self._Headers)

            oESResponse = json.loads(response.text)

    def getAllESSSCProjIssues(self):

        _url = '{}/sscprojissues/sscprojissues/_search?scroll=5m'.format(self._elasticUrl)
        logging.info(_url)

        _searchPost = {
            "size": 1000,
        }

        response = requests.get(_url, data=json.dumps(_searchPost), headers=self._Headers)

        oESResponse = json.loads(response.text)

        iTotalSSCProjIssuesCount = oESResponse['hits']['total']
        logging.info("Total SSC Project Issues in ES: {}".format(iTotalSSCProjIssuesCount))

        iCount4 = 0
        #while iCount < iTotalCount:
        while len(oESResponse['hits']['hits']) > 0:
            for oSscProjIssue in oESResponse['hits']['hits']:
                iCount4 = iCount4 + 1
                #logging.info(iCount4)
                self._allSSCProjectIssues.append(oSscProjIssue['_source'])

            #get the next batch
            _url = '{}/_search/scroll'.format(self._elasticUrl)
            _searchPost = {
                "scroll": "5m",
                "scroll_id": oESResponse['_scroll_id'],
            }

            response = requests.get(_url, data=json.dumps(_searchPost), headers=self._Headers)

            oESResponse = json.loads(response.text)

    def getAllESTestProjects(self):

        _url = '{}/testprojects/testprojects/_search?scroll=1m'.format(self._elasticUrl)
        logging.info(_url)

        _searchPost = {
            "size": 1000,
        }

        response = requests.get(_url, data=json.dumps(_searchPost), headers=self._Headers)

        oESResponse = json.loads(response.text)

        iTotalTestCount = oESResponse['hits']['total']
        logging.info("Total Test Projects in ES: {}".format(iTotalTestCount))

        tCount = 0
        #while iCount < iTotalCount:
        while len(oESResponse['hits']['hits']) > 0:
            for oTestProj in oESResponse['hits']['hits']:
                tCount = tCount + 1
                logging.info(tCount)
                self._allTestProjects.append(oTestProj['_source'])

            #get the next batch
            _url = '{}/_search/scroll'.format(self._elasticUrl)
            _searchPost = {
                "scroll": "1m",
                "scroll_id": oESResponse['_scroll_id'],
            }

            response = requests.get(_url, data=json.dumps(_searchPost), headers=self._Headers)

            oESResponse = json.loads(response.text)

    def getAllAppRelInfoReport(self):

        _url = '{}/apprelinforeport/apprelinforeport/_search?scroll=1m'.format(self._elasticUrl)
        logging.info(_url)

        _searchPost = {
            "size": 5000,
            "sort": [
                        "_ApplicationID",
                        "_ReleaseID" 
                        ],
            }

        #logging.info(_searchPost)
        response = requests.get(_url, data=json.dumps(_searchPost), headers=self._Headers)

        #logging.info(response)
        oESResponse = json.loads(response.text)

        #logging.info(oESResponse)

        iTotalARIRCount = oESResponse['hits']['total']
        logging.info("Total ARIR records in ES: {}".format(iTotalARIRCount))

        iCount = 0
        #while iCount < iTotalCount:
        while len(oESResponse['hits']['hits']) > 0:
            for oARIRrec in oESResponse['hits']['hits']:
                iCount = iCount + 1
                #logging.info(iCount)
                self._allARIRRecords.append(oARIRrec['_source'])

            #get the next batch
            _url = '{}/_search/scroll'.format(self._elasticUrl)
            _searchPost = {
                "scroll": "1m",
                "scroll_id": oESResponse['_scroll_id'],
            }

            response = requests.get(_url, data=json.dumps(_searchPost), headers=self._Headers)

            oESResponse = json.loads(response.text)
    