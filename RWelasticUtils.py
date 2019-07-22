from typing import Dict, List, Any, Union

import requests
import json
import time
import sys
import logging
from configLogging import configLogging

with open('settings.json') as json_data:
    settings = json.load(json_data)

configLogging(settings)

class elasticUtil:
    def __init__(self, url):
        self._elasticUrl = url

        self._Headers = {'Accept': 'application/json',
                         'Content-Type': 'application/json'
                         }
        self._allFODVuls = []
        self._allSSCIss = []


    def delESIndex(self, indexToDelete):

            _Headers = {'Accept': 'application/json',
                        'Content-Type': 'application/json'
                        }

            self.esdelind = {
                'status': 'OK',
                'status_code': 200,
                'response': 'OK'
            }

            url = "{}/{}".format(self._elasticUrl, indexToDelete)
            response = requests.delete(url, headers=_Headers)

            logging.info('Deletting Index: {} - {}'.format(indexToDelete, response.text))

            return self.esdelind


    
    def postFODReleases(self, jrel):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        self.postfodrels = {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
        }
        _url = '{}/fodrels/fodrels/'.format(self._elasticUrl)

        response = requests.post(_url, data=jrel,  headers = _Headers )

        #print(response.text)

        return self.postfodrels

    def mapVulnerabilities(self):

        self.delESIndex('fod_vulnerabilities')

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        '''
        {'releaseId': 1234, 'FixedIssue': 0, 'SuppressedIssues': 0}
        '''

        _url = '{}/fod_vulnerabilities'.format(self._elasticUrl)
        _mapping = {
            "mappings":{
                "fod_vulnerabilities":{
                    "properties":{
                        "releaseId": {"type": "integer"},
                        "FixedIssue": {"type": "integer"},
                        "SuppressedIssues": {"type": "integer"}
                    }
                }
            }
        }
        response = requests.put(_url, data=json.dumps(_mapping), headers=_Headers)

        logging.info('Mapping fod_vulnerabilities - {}'.format(response.text))

    
    def mapFODApplications(self):

        self.delESIndex('fodapplications')

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        _url = '{}/fodapplications'.format(self._elasticUrl)
        _mapping = {
            "mappings": {
                "fodapplications": {
                    "properties": {
                        "applicationId": {"type": "integer"},
                        "applicationName": {"type": "text"},
                        "applicationDescription": {"type": "text"},
                        "applicationCreatedDate": {"type": "date"},
                        "businessCriticalityTypeId": {"type": "integer"},
                        "businessCriticalityType": {"type": "text"},
                        "emailList": {"type": "text"},
                        "applicationTypeId": {"type": "integer"},
                        "applicationType": {"type": "text"},
                        "hasMicroservices": {"type": "boolean"},
                        "attributes": {"type": "nested",
                            "properties": {
                                "UAID": {"type": "text"},
                                "OOS?": {"type": "text"},
                                "EMD: Planning/Analysis": {"type": "text"},
                                "EMD: Remediation": {"type": "text"},
                                "EMD: Code Resubmission": {"type": "text"},
                                "RAG Status": {"type": "text"},
                                "APP STATUS": {"type": "text"},
                                "Subscription": {"type": "text"},
                                "Reason OOS": {"type": "text"},
                                "FoD Integration": {"type": "text"},
                                "Integration Date": {"type": "text"},
                                "Build Environment": {"type": "text"},
                                "Overall Application Status Comments": {"type": "text"},
                                "Reason not Integrated": {"type": "text"},
                                "OOS Language ": {"type": "text"}
                                       }
                                }
                    }
                }
            }
        }
        response = requests.put(_url, data=json.dumps(_mapping), headers=_Headers)

        logging.info('Mapping fodappcations - {}'.format(response.text))

    def postFODAppls(self, japp):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        self.postfodapplications = {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
        }

        url = '{}/fodapplications/fodapplications/'.format(self._elasticUrl)
        response = requests.post(url, data=japp, headers=_Headers)
        logging.info('posting fod applications: {} - {}'.format(japp, response.text))

        #print(response.text)

        return self.postfodapplications

    def postFODRels(self, jrel):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        self.postfodreleases = {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
        }
        _url = '{}/fodreleases/fodreleases/'.format(self._elasticUrl)

        response = requests.post(_url, data=jrel,  headers = _Headers )

        #print(response.text)

        return self.postfodreleases

    def mapFODCounts(self):

        self.delESIndex('fodcounts')

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        '''
        {'releaseId': 1234, 'FixedIssue': 0, 'SuppressedIssues': 0}
        '''

        _url = '{}/fodcounts'.format(self._elasticUrl)
        _mapping = {
            "mappings":{
                "fodcounts":{
                    "properties":{
                        "releaseId": {"type": "integer"},
                        "FixedIssue": {"type": "integer"},
                        "SuppressedIssues": {"type": "integer"}
                    }
                }
            }
        }
        response = requests.put(_url, data=json.dumps(_mapping), headers=_Headers)

        logging.info('Mapping fodcounts - {}'.format(response.text))

    def postFODCounts(self, _summary):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        self.postfodcounts = {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
        }

        url = '{}/fodcounts/fodcounts/{}'.format(self._elasticUrl, _summary['releaseId'])
        response = requests.post(url, data=json.dumps(_summary), headers=_Headers)

        logging.info(response.text)

    def mapFODScans(self):

        self.delESIndex('fodscans')

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        _url = '{}/fodscans'.format(self._elasticUrl)
        _mapping = {
            "mappings": {
                "fodscans": {
                    "properties": {
                        "applicationId": {"type": "integer"},
                        "applicationName": {"type": "text"},
                        "releaseId": {"type": "integer"},
                        "releaseName": {"type": "text"},
                        "scanId": {"type": "integer"},
                        "scanTypeId": {"type": "integer"},
                        "scanType": {"type": "text"},
                        "assessmentTypeId": {"type": "integer"},
                        "assessmentType": {"type": "text"},
                        "analysisStatusTypeId": {"type": "integer"},
                        "analysisStatusType": {"type": "text"},
                        "startedDateTime": {"type": "date"},
                        "completedDateTime": {"type":"date"},
                        "totalIssues": {"type": "integer"},
                        "issueCountCritical": {"type": "integer"},
                        "issueCountHigh": {"type": "integer"},
                        "issueCountMedium": {"type": "integer"},
                        "issueCountLow": {"type": "integer"},
                        "starRating": {"type": "integer"},
                        "notes": {"type": "text"},
                        "isFalsePositiveChallenge": {"type": "boolean"},
                        "isRemediationScan": {"type": "boolean"},
                        "entitlementId": {"type": "integer"},
                        "entitlementUnitsConsumed": {"type": "integer"},
                        "isSubscriptionEntitlement": {"type": "boolean"},
                        "pauseDetails": {"type": "nested",
                            "properties": {
                                "pausedOn": {"type": "date"},
                                "details": {"type": "text"},
                                "notes": {"type": "text"}
                                         }
                                },
                        "cancelReason": {"type": "text"}        
                    }
                }
            }
        }
        response = requests.put(_url, data=json.dumps(_mapping), headers=_Headers)

        logging.info('Mapping fodscans - {}'.format(response.text))

    def postFODScans(self, _summary):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        self.postfodscans = {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
        }

        url = '{}/fodscans/fodscans/'.format(self._elasticUrl)
        #logging.info(url)

        response = requests.post(url, data=json.dumps(_summary), headers=_Headers)

        #logging.info(response.text)

    def mapFODScanSummary(self):

        self.delESIndex('fodscansummary')

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        _url = '{}/fodscansummary'.format(self._elasticUrl)
        _mapping = {
            "mappings": {
                "fodscansummary": {
                    "properties": {
                        "startedByUserid": {"type": "integer"},
                        "startedByUserName": {"type": "text"},
                        "dynamicScanSummaryDetails": {"type": "nested",
                            "properties": {
                                "dynamicSiteURL": {"type": "text"},
                                "restrictToDirectoryAndSubdirectories": {"type":"boolean"},
                                "allowSameHostRedirects": {"type":"boolean"},
                                "allowFormSubmissions": {"type":"boolean"},
                                "timeZone": {"type": "text"},
                                "dynamicScanEnvironmentFacingType": {"type": "text"},
                                "hasAvailabilityRestrictions": {"type":"boolean"},
                                "requestCall": {"type":"boolean"},
                                "hasFormAuthentication": {"type":"boolean"},
                                "requiresNetworkAuthentication": {"type":"boolean"},
                                "isWebService": {"type":"boolean"},
                                "WebServiceType": {"type":"text"},
                                "userAgentType": {"type":"text"},
                                "notes": {"type":"text"},
                                "concurrentRequestThreadsType": {"type":"text"}
                                        }
                                },
                        "mobileScanSummaryDetails": {"type": "nested",
                            "properties": {
                                "frameworkType": {"type": "text"},
                                "auditPreferenceType": {"type":"text"},
                                "platformType": {"type":"text"},
                                "identifier": {"type":"text"},
                                "version": {"type": "text"},
                                "userAccountsRequired": {"type": "boolean"},
                                "accessToWebServices": {"type":"boolean"},
                                "hasExclusions": {"type":"boolean"},
                                "hasAvailabilityRestrictions": {"type":"boolean"}
                                        }
                                },
                        "staticScanSummaryDetails": {"type": "nested",
                            "properties": {
                                "technologyStack": {"type": "text"},
                                "languageLevel": {"type":"text"},
                                "doSonatypeScan": {"type":"boolean"},
                                "auditPreferenceType": {"type":"text"},
                                "excludeThirdPartyLibs": {"type": "boolean"},
                                "buildDate": {"type": "date"},
                                "engineVersion": {"type":"text"},
                                "rulePackVersion": {"type":"text"},
                                "fileCount": {"type":"integer"},
                                "totalLinesOfCode": {"type":"integer"},
                                "payLoadSize": {"type":"text"}
                                        }
                                },
                        "applicationId": {"type": "integer"},
                        "applicationName": {"type": "text"},
                        "releaseId": {"type": "integer"},
                        "releaseName": {"type": "text"},
                        "scanId": {"type": "integer"},
                        "scanTypeId": {"type": "integer"},
                        "scanType": {"type": "text"},
                        "assessmentTypeId": {"type": "integer"},
                        "assessmentTypeName": {"type": "text"},
                        "analysisStatusTypeId": {"type": "integer"},
                        "analysisStatusType": {"type": "text"},
                        "startedDateTime": {"type": "date"},
                        "completedDateTime": {"type":"date"},
                        "totalIssues": {"type": "integer"},
                        "issueCountCritical": {"type": "integer"},
                        "issueCountHigh": {"type": "integer"},
                        "issueCountMedium": {"type": "integer"},
                        "issueCountLow": {"type": "integer"},
                        "starRating": {"type": "integer"},
                        "notes": {"type": "text"},
                        "isFalsePositiveChallenge": {"type": "boolean"},
                        "isRemediationScan": {"type": "boolean"},
                        "entitlementId": {"type": "integer"},
                        "entitlementUnitsConsumed": {"type": "integer"},
                        "isSubscriptionEntitlement": {"type": "boolean"},
                        "pauseDetails": {"type": "nested",
                            "properties": {
                                "pausedOn": {"type": "date"},
                                "details": {"type": "text"},
                                "notes": {"type": "text"}
                                         }
                                },
                        "cancelReason": {"type": "text"}
                     }
                }
            }
        }
        response = requests.put(_url, data=json.dumps(_mapping), headers=_Headers)

        logging.info('Mapping fodscansummary - {}'.format(response.text))

    def postFODScanSummary(self, _summary):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        self.postfodscansummary = {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
        }

        url = '{}/fodscansummary/fodscansummary/'.format(self._elasticUrl)
        response = requests.post(url, data=json.dumps(_summary), headers=_Headers)

        #logging.info(response.text)


    def mapFODRelIssues(self):

        self.delESIndex('fodrelissues')
        self.delESIndex('fodrelissue')
        
        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }
        
        _url = '{}/fodrelissues'.format(self._elasticUrl)
        _mapping = {
            "mappings": {
                "fodrelissues": {
                    "properties": {
                        "id": {"type": "integer"},
                        "releaseId": {"type": "integer"},
                        "fisma": {"type": "text"},
                        "severityString": {"type": "text"},
                        "severity": {"type": "integer"},
                        "category": {"type": "text"},
                        "kingdom": {"type":"text"},
                        "owasp2004": {"type": "text"},
                        "owasp2007": {"type": "text"},
                        "owasp2010": {"type": "text"},
                        "owasp2013": {"type": "text"},
                        "owasp2017": {"type": "text"},
                        "cwe": {"type": "text"},
                        "package": {"type": "text"},
                        "primaryLocation": {"type": "text"},
                        "vulnId": {"type": "text"},
                        "analysisType": {"type": "text"},
                        "lineNumber": {"type": "integer"},
                        "hasComments": {"type": "boolean"},
                        "assignedUser": {"type": "text"},
                        "scantype": {"type": "text"},
                        "subtype": {"type": "text"},
                        "primaryLocationFull": {"type": "text"},
                        "hasAttachments": {"type": "boolean"},
                        "pci1_1": {"type": "text"},
                        "pci1_2": {"type": "text"},
                        "pci2": {"type": "text"},
                        "sans2009": {"type": "text"},
                        "sans2010": {"type": "text"},
                        "sans2011": {"type": "text"},
                        "wasc24_2": {"type": "text"},
                        "isSuppressed": {"type": "boolean"},
                        "scanId": {"type": "integer"},
                        "pci3": {"type":"text"},
                        "instanceId": {"type": "text"},
                        "auditPendingAuditorStatus": {"type": "text"},
                        "auditorStatus": {"type": "text"},
                        "checkId": {"type": "text"},
                        "closedDate": {"type": "date"},
                        "closedStatus": {"type": "boolean"},
                        "developerStatus": {"type": "text"},
                        "falsePositiveChallenge": {"type": "text"},
                        "introducedDate": {"type": "date"},
                        "scanStartedDate": {"type": "date"},
                        "scanCompletedDate": {"type": "date"},
                        "status": {"type": "text"},
                        "bugSubmitted": {"type": "boolean"},
                        "bugLink": {"type": "text"},
                        "auditPendingSuppression": {"type": "text"},
                        "source": {"type": "text"},
                        "sink": {"type": "text"},
                        "timeToFixDays": {"type": "integer"}
                    }
                }
            }
        }
        response = requests.put(_url, data=json.dumps(_mapping), headers=_Headers)

        logging.info('Mapping fodrelissues - {}'.format(response.text))
    

    def postFODRelIssues(self, _issue):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        self.postfodrelissue = {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
        }

        url = '{}/fodrelissues/fodrelissues/'.format(self._elasticUrl)
        response = requests.post(url, data=json.dumps(_issue), headers=_Headers)

        #logging.info(response.text)


    def mapSSCProjects(self):

        self.delESIndex('sscprojects')

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }
        
        _url = '{}/sscprojects'.format(self._elasticUrl)
        _mapping = {
            "mappings": {
                "sscprojects": {
                    "properties": {
                        "_href": {"type": "text"},
                        "name": {"type": "text"},
                        "project": {"type": "nested",
                            "properties": {
                                "id": {"type": "integer"},
                                "name": {"type": "text"},
                                "description": {"type": "text"},
                                "creationDate": {"type": "date"},
                                "createdBy": {"type": "text"},
                                "issueTemplateId": {"type": "text"}
                                }
                            },
                        "id": {"type": "integer"},
                        "issueTemplateId": {"type":"text"},
                        "currentState": {"type": "nested",
                            "properties": {
                                "id": {"type": "integer"},
                                "committed": {"type": "boolean"},
                                "attentionRequired": {"type": "boolean"},
                                "analysisResultsExist": {"type": "boolean"},
                                "auditEnabled": {"type": "boolean"},
                                "lastFPRUploadDate": {"type": "date"},
                                "extraMessage": {"type": "boolean"},
                                "analysisUploadEnables": {"type": "boolean"},
                                "batchBugSubmissionExists": {"type": "boolean"},
                                "hasCustomIssues": {"type": "boolean"},
                                "metricEvaluationDate": {"type": "date"},
                                "deltaPeriod": {"type": "integer"},
                                "issueCountDelta": {"type": "integer"},
                                "percentAuditedDelta": {"type": "double"},
                                "criticalPriorityIssueContDelta": {"type":"integer"},
                                "percentCriticalPriorityIssueAuditedDelta": {"type": "double"}
                                       }
                                }
                    }
                }
            }
        }
        response = requests.put(_url, data=json.dumps(_mapping), headers=_Headers)

        logging.info('Mapping sscprojects - {}'.format(response.text))


    def postSSCProjects(self, jproject):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        self.postsscproj = {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
        }

        url = '{}/sscprojects/sscprojects/'.format(self._elasticUrl)
        response = requests.post(url, data=jproject, headers=_Headers)
        #logging.info('posting projects: {} - {}'.format(jproject, response.text))

        #print(response.text)

        return self.postsscproj
    

    def mapSSCProjCounts(self):

        self.delESIndex('sscprojcounts')

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }
        
        _url = '{}/sscprojcounts'.format(self._elasticUrl)
        _mapping = {
            "mappings": {
                "sscprojcounts": {
                    "properties": {
                        "projectVersionId": {"type": "integer"},
                        "critical": {"type": "integer"},
                        "high": {"type": "integer"},
                        "medium": {"type": "integer"},
                        "low": {"type": "integer"},
                        "count": {"type": "integer"},
                        "hiddenCount": {"type": "integer"},
                        "suppressedCount": {"type": "integer"},
                        "removedCount": {"type": "integer"}
                    }
                }
            }
        }
        response = requests.put(_url, data=json.dumps(_mapping), headers=_Headers)

        logging.info('Mapping sscprojcounts - {}'.format(response.text))

    
    def postSSCProjCounts(self, jprojcount):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        self.postsscprojcount = {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
        }

        url = '{}/sscprojcounts/sscprojcounts/'.format(self._elasticUrl)
        response = requests.post(url, data=jprojcount, headers=_Headers)
        #logging.info('posting projcounts: {} - {}'.format(jprojcount, response.text))

        #print(response.text)

        return self.postsscprojcount


    def mapSSCProjAttributes(self):

        self.delESIndex('sscprojattrs')

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }
        
        _url = '{}/sscprojattrs'.format(self._elasticUrl)
        _mapping = {
            "mappings": {
                "sscprojattrs": {
                    "properties": {
                        "projectVersionId": {"type": "integer"},
                        "attributerec": {"type": "nested",
                            "properties": {
                                "_href": {"type": "text"},
                                "attributeDefinitionId": {"type": "integer"},
                                "values": {"type": "nested",
                                    "properties": {
                                        "id": {"type": "integer"},
                                        "guid": {"type": "text"},
                                        "name": {"type": "text"},
                                        "decscription": {"type": "text"},
                                        "hidden": {"type": "boolean"},
                                        "inUse": {"type": "boolean"},
                                        "index": {"type": "integer"},
                                        "projectMetaDataDefId": {"type": "integer"},
                                        "publishVersion": {"type": "double"},
                                        "objectVersion": {"type": "double"},
                                        }
                                    },
                                "guid": {"type": "text"},
                                "id": {"type": "integer"},
                                "value": {"type": "integer"}
                            }
                        }            
                    }
                }
            }
        }
        response = requests.put(_url, data=json.dumps(_mapping), headers=_Headers)

        logging.info('Mapping sscprojattrs - {}'.format(response.text))

    def postSSCProjAttrs(self, projid, jprojattrs):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        holddata = {'projectVersionId': projid,
                    'attributerec': jprojattrs}
        
        #logging.info(holddata)

        self.postsscprojattrs = {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
        }

        url = '{}/sscprojattrs/sscprojattrs/'.format(self._elasticUrl)
        response = requests.post(url, data=json.dumps(holddata), headers=_Headers)
        #logging.info('posting projattrs: {} - {}'.format(holddata, response.text))

        #print(response.text)

        return self.postsscprojattrs

    def mapSSCProjScans(self):

        self.delESIndex('sscprojscans')

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }
        
        _url = '{}/sscprojscans'.format(self._elasticUrl)
        _mapping = {
            "mappings": {
                "sscprojscans": {
                    "properties": {
                        "projectVersionId": {"type": "integer"},
                        "scanrec": {"type": "nested",
                            "properties": {
                                "artifactType": {"type": "text"},
                                "fileName": {"type": "text"},
                                "approvalDate": {"type": "date"},
                                "messageCount": {"type": "integer"},
                                "_embed": {"type": "nested",
                                    "properties": {
                                    "scans": {"type": "nested",
                                        "properties": {
                                            "id": {"type": "integer"},
                                            "guid": {"type": "text"},
                                            "uploadDate": {"type": "date"},
                                            "type": {"type": "text"},
                                            "certification": {"type": "text"},
                                            "hostname": {"type": "text"},
                                            "engineVersion": {"type": "text"},
                                            "artifactId": {"type":"integer"},
                                            "buildlabel": {"type": "text"},
                                            "noOfFiles": {"type": "integer"},
                                            "totalLOC": {"type": "integer"},
                                            "execLOC": {"type": "integer"},
                                            "elapsedTime": {"type": "text"},
                                            "fortifyAnnotationsLOC": {"type": "text"},
                                            }
                                        },
                                    }
                                },
                                "scanErrorsCount": {"type": "integer"},
                                "uploadIP": {"type": "text"},
                                "allowApprove": {"type": "boolean"},
                                "allowPurge": {"type": "boolean"},
                                "lastScanDate": {"type": "date"},
                                "fileURL": {"type": "text"},
                                "id": {"type": "integer"},
                                "purged": {"type": "boolean"},
                                "webInspectStatus": {"type":"text"},
                                "inModifyingStatus": {"type": "boolean"},
                                "originalFileName": {"type": "text"},
                                "allowDelete": {"type": "boolean"},
                                "_href": {"type": "text"},
                                "scaStatus": {"type": "text"},
                                "indexed": {"type": "boolean"},
                                "runtimeStatus": {"type":"text"},
                                "userName": {"type": "text"},
                                "versionNumber": {"type": "text"},
                                "otherStatus": {"type": "text"},
                                "uploadDate": {"type":"date"},
                                "approvalComment": {"type": "text"},
                                "approvalUsername": {"type": "text"},
                                "fileSize": {"type": "integer"},
                                "messages": {"type": "text"},
                                "auditUpdated": {"type": "boolean"},
                                "status": {"type": "text"}
                            }
                        }            
                    }
                }
            }
        }

        response = requests.put(_url, data=json.dumps(_mapping), headers=_Headers)

        logging.info('Mapping sscprojscans - {}'.format(response.text))

    def postSSCProjScans(self, projid, jprojscans):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        holddata = {'projectVersionId': projid,
                    'scanrec': jprojscans}
        
        #logging.info(holddata)

        self.postsscprojscans = {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
        }

        url = '{}/sscprojscans/sscprojscans/'.format(self._elasticUrl)
        response = requests.post(url, data=json.dumps(holddata), headers=_Headers)
        #logging.info('posting projscans: {} - {}'.format(holddata, response.text))

        #print(response.text)

        return self.postsscprojscans


    def mapSSCProjIssues(self):

        self.delESIndex('sscprojissues')
        
        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }
        
        _url = '{}/sscprojissues'.format(self._elasticUrl)
        _mapping = {
            "mappings": {
                "sscprojissues": {
                    "properties": {
                        "bugURL": {"type": "text"},
                        "hidden": {"type": "boolean"},
                        "issueName": {"type": "text"},
                        "folderGuid": {"type": "text"},
                        "lastScanId": {"type": "integer"},
                        "engineType": {"type":"text"},
                        "issueStatus": {"type": "text"},
                        "friority": {"type": "text"},
                        "analyzer": {"type": "text"},
                        "primaryLocation": {"type": "text"},
                        "reviewed": {"type": "text"},
                        "id": {"type": "integer"},
                        "suppressed": {"type": "boolean"},
                        "hasAttachments": {"type": "boolean"},
                        "engineCategory": {"type": "text"},
                        "projectVersionName": {"type": "text"},
                        "removedDate": {"type": "date"},
                        "severity": {"type": "double"},
                        "_href": {"type": "text"},
                        "displayEngineType": {"type": "text"},
                        "foundDate": {"type": "date"},
                        "confidence": {"type": "double"},
                        "impact": {"type": "double"},
                        "primaryRuleGuid": {"type": "text"},
                        "projectVersionId": {"type": "integer"},
                        "scanStatus": {"type":"text"},
                        "audited": {"type": "boolean"},
                        "kingdom": {"type": "text"},
                        "folderId": {"type": "integer"},
                        "revision": {"type": "integer"},
                        "likelihood": {"type": "double"},
                        "removed": {"type": "boolean"},
                        "issueInstanceId": {"type": "text"},
                        "hasCorrelatedIssues": {"type": "boolean"},
                        "primaryTag": {"type": "text"},
                        "lineNumber": {"type": "integer"},
                        "projectName": {"type": "text"},
                        "fullFileName": {"type": "text"},
                        "primaryTagValueAutoApplied": {"type": "boolean"}
                    }
                }
            }
        }
        response = requests.put(_url, data=json.dumps(_mapping), headers=_Headers)

        logging.info('Mapping sscprojissues - {}'.format(response.text))

    def postSSCProjIssues(self, _issues):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        self.postsscissues = {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
        }

        
        url = '{}/sscprojissues/sscprojissues/'.format(self._elasticUrl)
        response = requests.post(url, data=_issues, headers=_Headers)
        #logging.info('posting sscprojissues: {} - {}'.format(_issues, response.text))

        return self.postsscissues


    

    def postFODVulnerabilities(self, _summary):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        self.postfodappl = {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
        }

        url = '{}/fod_vulnerabilities/fod_vulnerabilities/{}'.format(self._elasticUrl, _summary['releaseId'])
        response = requests.post(url, data=json.dumps(_summary), headers=_Headers)

        logging.info(response.text)

    def postFODVulner(self, _vulner):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        self.postfodvuln = {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
        }

        
        url = '{}/fod_vulner/fod_vulner/'.format(self._elasticUrl)

        
        response = requests.post(url, data=_vulner, headers=_Headers)

        logging.info('******')
        logging.info(response.text)

        return self.postfodvuln

    def postSSCIssues(self, _issues):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        self.postsscissues = {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
        }

        
        url = '{}/ssc_issues/ssc_issues/'.format(self._elasticUrl)

        
        response = requests.post(url, data=_issues, headers=_Headers)

        logging.info('******')
        logging.info(response.text)

        return self.postsscissues


    def postSSCProjectVersion(self, url, jsonProjectVersion):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        response = requests.post(url, data=jsonProjectVersion,  headers = _Headers )

        logging.info(response.text)

        return {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
            }

    def searchSSCforUAID(self, UAID):

        url = ('{}/sscprojectversions/_search'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "project.name": UAID
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

        return  json.loads(response.text)

    def searchSSCProjectsforProjectId(self, projid):

        url = ('{}/sscprojects/_search'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "id": projid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

        #print(response.text)

        return  json.loads(response.text)

    def searchSSCProjectCountsforProjectId(self, projid):

        url = ('{}/sscprojcounts/_search'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "projectVersionId": projid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

        #print(response.text)

        return  json.loads(response.text)


    def searchSSCProjectIssuesforProjectId(self, projid):

        url = ('{}/sscprojissues/_search'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "projectVersionId": projid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

        #print(response.text)

        return  json.loads(response.text)

    def searchSSCProjectIssuesforElasticId(self, elasticid):

        url = ('{}/sscprojissues/_search'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "_id": elasticid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

        #print(response.text)

        return  json.loads(response.text)

    def deleteSSCProjectIssuesbyElasticId(self, elasticid):

        url = ('{}/sscprojissues/sscprojissues/_delete_by_query'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "_id": elasticid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

       #print(response.text)

        return  json.loads(response.text)


    def searchSSCProjectIssuesforProjectIdandIssueId(self, projid, issueId):

        url = ('{}/sscprojissues/_search'.format(self._elasticUrl))

        _post ={
                "query": {
                    "bool": {
                        "must": [
                        {
                            "term": {
                                "projectVersionId": projid,
                            }
                        },
                        {
                            "term": {                        
                                "id": issueId
                            }
                       }
                    ]
                }
            }
        }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

        #print(response.text)

        return  json.loads(response.text)


    def deleteSSCProjectIssuesbyProjectIdandIssueId(self, projid, issueId):

        url = ('{}/sscprojissues/sscprojissues/_delete_by_query'.format(self._elasticUrl))

        _post ={
                "query": {
                    "bool": {
                        "must": [
                        {
                            "term": {
                                "projectVersionId": projid,
                            }
                        },
                        {
                            "term": {                        
                                "id": issueId
                            }
                       }
                    ]
                }
            }
        }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

       #print(response.text)

        return  json.loads(response.text)    


    def searchSSCProjectIssuesforRemovedBadDate(self):

        trueval = False
        iRecToReturn = 500

        url = ('{}/sscprojissues/_search?scroll=5m'.format(self._elasticUrl))

        _post ={
                "size": iRecToReturn,
                "sort": [
                        "projectVersionId" 
                        ],
                "query": {
                    "bool": {
                        "must": [
                        {
                            "term": {                        
                                "removed": trueval
                            }
                       }
                    ]
                }
            }
        }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

        #print(response.text)

        return  json.loads(response.text)


    def searchSSCProjectIssuesforIssueName(self, issueName):

        url = ('{}/sscprojissues/_search'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "issueName": issueName
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

        #print(response.text)

        return  json.loads(response.text)

    def aggregSSCProjectIssuesforDistinctProjVersId(self):

        url = ('{}/sscprojissues/_search'.format(self._elasticUrl))

        _post ={
                "size": 0,
                "aggs": {
                    "distinct projectVersionId" : {
                    "terms": {
                        "field" : "projectVersionId",
                        "size": 10000
                        }
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

        #print(response.text)

        return  json.loads(response.text)

    def getAllESFODVulner(self):

        _url = '{}/fod_vulner/_search?scroll=1m'.format(self._elasticUrl)
        logging.info(_url)

        _searchPost = {
            "size": 1000,
        }

        response = requests.post(_url, data=json.dumps(_searchPost), headers=self._Headers)

        oESResponse = json.loads(response.text)

        iTotalCount = oESResponse['hits']['total']
        logging.info("Total FOD Vulnerabilities in ES: {}".format(iTotalCount))

        iCount = 0
        #while iCount < iTotalCount:
        while len(oESResponse['hits']['hits']) > 0:
            for oFodVul in oESResponse['hits']['hits']:
                iCount = iCount + 1
                self._allFODVuls.append(oFodVul['_source'])

            #get the next batch
            _url = '{}/_search/scroll'.format(self._elasticUrl)
            _searchPost = {
                "scroll": "1m",
                "scroll_id": oESResponse['_scroll_id'],
            }

            response = requests.post(_url, data=json.dumps(_searchPost), headers=self._Headers)

            oESResponse = json.loads(response.text)

    def getAllESSSCIssues(self):

        _url = '{}/ssc_issues/_search?scroll=1m'.format(self._elasticUrl)
        logging.info(_url)

        _searchPost = {
            "size": 1000,
        }

        response = requests.post(_url, data=json.dumps(_searchPost), headers=self._Headers)

        oESResponse = json.loads(response.text)

        iTotalCount = oESResponse['hits']['total']
        logging.info("Total SSC Issues in ES: {}".format(iTotalCount))

        iCount = 0
        #while iCount < iTotalCount:
        while len(oESResponse['hits']['hits']) > 0:
            for oSSCIss in oESResponse['hits']['hits']:
                iCount = iCount + 1
                self._allSSCIss.append(oSSCIss['_source'])

            #get the next batch
            _url = '{}/_search/scroll'.format(self._elasticUrl)
            _searchPost = {
                "scroll": "1m",
                "scroll_id": oESResponse['_scroll_id'],
            }

            response = requests.post(_url, data=json.dumps(_searchPost), headers=self._Headers)

            oESResponse = json.loads(response.text)

    def postSSCProjectTest(self, jproject):

        _Headers = {'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }

        self.posttestproj = {
            'status': 'OK',
            'status_code': 200,
            'response': 'OK'
        }

        url = '{}/testprojects/testprojects/'.format(self._elasticUrl)
        response = requests.post(url, data=jproject, headers=_Headers)
        logging.info('posting test projects: {} - {}'.format(jproject, response.text))

        #print(response.text)

        return self.posttestproj

    def searchTestProjectsforProjectId(self, projid):

        url = ('{}/testprojects/_search'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "id": projid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

        #print(response.text)

        return  json.loads(response.text)

    def searchTestProjectsforProjectIdandIssueTemplateId(self, projid, issueTemplate):

        url = ('{}/testprojects/_search'.format(self._elasticUrl))

        _post ={
                "query": {
                    "bool": {
                        "must": [
                        {
                            "term": {
                                "id": projid,
                            }
                        },
                        {
                            "term": {                        
                                "project.id": issueTemplate
                            }
                       }
                    ]
                }
            }
        }

        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

        #print(response.text)

        return  json.loads(response.text)

    def deleteTestProjectsbyProjectId(self, projid):

        url = ('{}/testprojects/testprojects/_delete_by_query'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "id": projid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

       #print(response.text)

        return  json.loads(response.text)

    def deleteTestProjectsbyProjectIdandIssueTemplateId(self, projid, issueTemplate):

        url = ('{}/testprojects/testprojects/_delete_by_query'.format(self._elasticUrl))

        _post ={
                "query": {
                    "bool": {
                        "must": [
                        {
                            "term": {
                                "id": projid,
                            }
                        },
                        {
                            "term": {                        
                                "project.id": issueTemplate
                            }
                       }
                    ]
                }
            }
        }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

       #print(response.text)

        return  json.loads(response.text)

    def deleteSSCProjectsbyProjectId(self, projid):

        url = ('{}/sscprojects/sscprojects/_delete_by_query'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "id": projid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

       #print(response.text)

        return  json.loads(response.text)

    def deleteSSCProjectCountsbyProjectId(self, projid):

        url = ('{}/sscprojcounts/sscprojcounts/_delete_by_query'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "projectVersionId": projid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

       #print(response.text)

        return  json.loads(response.text)

    def deleteSSCProjectAttrsbyProjectId(self, projid):

        url = ('{}/sscprojattrs/sscprojattrs/_delete_by_query'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "projectVersionId": projid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

       #print(response.text)

        return  json.loads(response.text)

    def deleteSSCProjectScansbyProjectId(self, projid):

        url = ('{}/sscprojscans/sscprojscans/_delete_by_query'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "projectVersionId": projid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

       #print(response.text)

        return  json.loads(response.text)

    def deleteSSCProjectIssuesbyProjectId(self, projid):

        url = ('{}/sscprojissues/sscprojissues/_delete_by_query'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "projectVersionId": projid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

       #print(response.text)

        return  json.loads(response.text)

    
    def deleteFODApplicationsbyApplicationId(self, applid):

        url = ('{}/fodapplications/fodapplications/_delete_by_query'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "applicationId": applid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

       #print(response.text)

        return  json.loads(response.text)

    

    def deleteFODReleasesbyReleaseId(self, releaseid):

        url = ('{}/fodreleases/fodreleases/_delete_by_query'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "releaseId": releaseid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

       #print(response.text)

        return  json.loads(response.text)

    def deleteFODCountsbyReleaseId(self, releaseid):

        url = ('{}/fodcounts/fodcounts/_delete_by_query'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "releaseId": releaseid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

       #print(response.text)

        return  json.loads(response.text)

    def deleteFODScansbyReleaseId(self, releaseid):

        url = ('{}/fodscans/fodscans/_delete_by_query'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "releaseId": releaseid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

       #print(response.text)

        return  json.loads(response.text)

    def deleteFODScanSummarybyReleaseId(self, releaseid):

        url = ('{}/fodscansummary/fodscansummary/_delete_by_query'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "releaseId": releaseid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

       #print(response.text)

        return  json.loads(response.text)

    def deleteFODRelIssuesbyReleaseId(self, releaseid):

        url = ('{}/fodrelissues/fodrelissues/_delete_by_query'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "releaseId": releaseid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

       #print(response.text)

        return  json.loads(response.text)


    def searchFODReleasesforReleaseId(self, releaseid):

        url = ('{}/fodreleases/_search'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "releaseId": releaseid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

        #print(response.text)

        return  json.loads(response.text)

    def searchFODCountsforReleaseId(self, releaseid):

        url = ('{}/fodcounts/_search'.format(self._elasticUrl))

        _post ={
                "query": {
                    "match_phrase": {
                        "releaseId": releaseid
                    }
                }
            }


        response = requests.post(url, data=json.dumps(_post), headers=self._Headers)

        #print(response.text)

        return  json.loads(response.text)