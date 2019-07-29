import requests
from requests.auth import HTTPBasicAuth
from RWelasticUtils import elasticUtil
import json
import sys
import logging



'''
    SSC Utils
'''

class sscUtils:

    def __init__(self):
        self.projectVersions = {'data': [], 'count': 0}


        self.allIssues = {'data': [], 'Critical': 0, 'High': 0, 'Medium': 0, 'Low':0, 'count': 0}
        

     

    def sscAuth(self, user, password):

        self.sscUser = user
        self.sscPassword = password
        
        self.headers = {'Accept':'application/json',
            'Content-Type':'application/json'
            }

    def getProjectVersionIssueCounts(self, id):

        _issueCounts = {
            'projectVersionId': id,
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'count': 0,
            'hiddenCount': 0, 'suppressedCount': 0, 'removedCount': 0
        }

        #_url = 'https://fortify.1dc.com/ssc/api/v1/projectVersions/{}/issueGroups?groupingtype=11111111-1111-1111-1111-111111111150&filterset=a243b195-0a59-3f8b-1403-d55b7a7d78e6&filter=FOLDER:b968f72f-cc12-03b5-976e-ad4c13920c21&qm=issues&showhidden=false&showremoved=false&showshortfileNames=true&showsuppressed=false'.format(id)
        _url = 'https://fortify.1dc.com/ssc/api/v1/projectVersions/{}/issueGroups?groupingtype=11111111-1111-1111-1111-111111111150&filterset=a243b195-0a59-3f8b-1403-d55b7a7d78e6&qm=issues&showhidden=false&showremoved=false&showshortfileNames=true&showsuppressed=false'.format(id)

        response = requests.get(_url, auth=HTTPBasicAuth(self.sscUser, self.sscPassword), headers=self.headers)
        counts = json.loads(response.text)

        try:
        
            for count in counts['data']:
                if count['cleanName'] == "Critical":
                    _issueCounts['critical'] = count['visibleCount']

                elif count['cleanName'] == "High":
                    _issueCounts['high'] = count['visibleCount']
                elif count['cleanName'] == "Medium":
                    _issueCounts['medium'] = count['visibleCount']
                elif count['cleanName'] == "Low":
                    _issueCounts['low'] = count['visibleCount']
                else:
                    logging.info('odd: {}'.format(count['cleanName']))

            _issueCounts['count'] = _issueCounts['critical'] + _issueCounts['high'] + _issueCounts['medium'] + _issueCounts['low']    
        
        except KeyError:
            _issueCounts['critical'] = 0
            _issueCounts['high'] = 0
            _issueCounts['medium'] = 0
            _issueCounts['low'] = 0
            logging.info('error getting count totals - force recalc')

        
        _summaryHidden = self.getProjectVersionSummaryCounts(id)

        try:

            #_issueCounts['hiddenCount'] = _summaryHidden['data'][0]['hiddenCount']
            _issueCounts['suppressedCount'] = _summaryHidden['data'][0]['suppressedCount']
            _issueCounts['removedCount'] = _summaryHidden['data'][0]['removedCount']

        except KeyError:

            _issueCounts['suppressedCount'] = 0
            _issueCounts['removedCount'] = 0
            logging.info('error getting count totals - force recalc')


        return _issueCounts

    def getProjectVersionIssueCountsHidden(self, id):

        _issueCountsHidden = {
            'projectVersionId': id,
            'hiddenCount': 0
        }
               
        _summaryHidden = self.getProjectVersionSummaryCounts(id)

        try:

            _issueCountsHidden['hiddenCount'] = _summaryHidden['data'][0]['hiddenCount']
            
        except KeyError:

            _issueCountsHidden['hiddenCount'] = 0
            logging.info('error getting count totals - force recalc')


        return _issueCountsHidden

    def getProjectVersionLOCCounts(self, id):

        _url = 'https://fortify.1dc.com/ssc/api/v1/projectVersions/{}/artifacts?embed=scans&start=0&limit=1000'.format(id)

        response = requests.get(_url, auth=HTTPBasicAuth(self.sscUser, self.sscPassword), headers=self.headers)
        LOCcounts = json.loads(response.text)

        

        return LOCcounts

    def getProjectVersionScans(self, id):

        _url = 'https://fortify.1dc.com/ssc/api/v1/projectVersions/{}/artifacts?embed=scans&start=0&limit=1000'.format(id)

        response = requests.get(_url, auth=HTTPBasicAuth(self.sscUser, self.sscPassword), headers=self.headers)
        PVscans = json.loads(response.text)
   

        return PVscans

    def getProjectVersionAttributes(self, id):

        _url = 'https://fortify.1dc.com/ssc/api/v1/projectVersions/{}/attributes'.format(id)

        response = requests.get(_url, auth=HTTPBasicAuth(self.sscUser, self.sscPassword), headers=self.headers)
        PVattrs = json.loads(response.text)
 

        return PVattrs

    def getCloudscanJob(self):

        _url = 'https://fortify.1dc.com/ssc/api/v1/cloudjobs?start=-1&limit=-1'

        response = requests.get(_url, auth=HTTPBasicAuth(self.sscUser, self.sscPassword), headers=self.headers)
        CloudScanJobs = json.loads(response.text)

        

        return CloudScanJobs



    def getProjectVersionSummaryCounts(self, id):

        _url = 'https://fortify.1dc.com/ssc/api/v1/projectVersions/{}/issueStatistics?filterset=a243b195-0a59-3f8b-1403-d55b7a7d78e6'.format(id)

        response = requests.get(_url, auth=HTTPBasicAuth(self.sscUser, self.sscPassword), headers=self.headers)

        _hiddens = json.loads(response.text)
        

        return _hiddens


    def getProjectVersionIssueDetail(self, projid, issueid):

        _url = 'https://fortify.1dc.com/ssc/api/v1/projectVersions/{}/issues/{}'.format(projid, issueid)

        response = requests.get(_url, auth=HTTPBasicAuth(self.sscUser, self.sscPassword), headers=self.headers)

        _detail = json.loads(response.text)
        

        return _detail



    def getProjectVersionIssues(self, id):


        _issues = {'data': [], 'count': 0}
        
        _url = 'https://fortify.1dc.com/ssc/api/v1/projectVersions/{}/issues?start=0&limit=3000&showhidden=true&showremoved=true&showsuppressed=true&showshortfilenames=true'.format(id)

        _moreRecords = True

        iCurrentRecord = 0

        while _moreRecords:

            response = requests.get(_url, auth=HTTPBasicAuth(self.sscUser, self.sscPassword), headers=self.headers)
            issues = json.loads(response.text)

            if _issues['count'] == 0:
                _issues['count'] = issues['count']
                logging.info('Downloading for {} issues'.format(_issues['count']))
            else:
                logging.info('Downloading at {} - {} of {} total records'.format(iCurrentRecord, len(issues['data']), _issues['count']))

            for issue in issues['data']:
                iCurrentRecord = iCurrentRecord + 1
                _issues['data'].append(issue)
                                   
            try:
                _url = issues['links']['next']['href']
        
            except KeyError:
                _moreRecords = False
                logging.info('no more records to download')
            except:
                _moreRecords = False
                logging.info('something else happened trying to get next href')
                '''print('In getProjectVersionIssues - Unexpected error:{}'.format(sys.exc_info()[0]))
                '''

        
        return _issues
        

    def getAndLoadProjectVersionIssues(self, id, elasticUrl):

        es = elasticUtil(elasticUrl)

        _issues = {'data': [], 'count': 0}
        
        _url = 'https://fortify.1dc.com/ssc/api/v1/projectVersions/{}/issues?start=0&limit=500&showhidden=false&showremoved=true&showsuppressed=true&showshortfilenames=true'.format(id)

        _moreRecords = True

        iCurrentRecord = 0

        while _moreRecords:

            response = requests.get(_url, auth=HTTPBasicAuth(self.sscUser, self.sscPassword), headers=self.headers)
            issues = json.loads(response.text)

            
            if _issues['count'] == 0:
                _issues['count'] = issues['count']
                logging.info('Downloading for {} issues'.format(_issues['count']))
            else:
                logging.info('Downloading at {} - {} of {} total records'.format(iCurrentRecord, len(issues['data']), _issues['count']))

            for issue in issues['data']:
                iCurrentRecord = iCurrentRecord + 1

                #logging.info(issue)

                '''if (issue['hidden'] == False and issue['suppressed'] == False and issue['removed'] == True):
                    holdproj = issue['projectVersionId']
                    holdissue = issue['id']

                    #logging.info ('getting detail for {} issue {}'.format(holdproj, holdissue))

                    detail = self.getProjectVersionIssueDetail(holdproj,holdissue)
                    #logging.info(detail)
                    try:

                        holdnewdate = detail['data']['removedDate']

                    except KeyError:
                    
                        holdnewdate = None
                        logging.info ('error getting detail for {} issue {}'.format(holdproj, holdissue))  

                    #logging.info('new removed date {}'.format(holdnewdate))

                    issue['removedDate'] = holdnewdate

                    #logging.info(issue)'''

                es.postSSCProjIssues(json.dumps(issue))
                #_issues['data'].append(issue)
                                   
            try:
                _url = issues['links']['next']['href']
        
            except KeyError:
                _moreRecords = False
                logging.info('no more records to download')
            except:
                _moreRecords = False
                logging.info('something else happened trying to get next href')
                '''print('In getProjectVersionIssues - Unexpected error:{}'.format(sys.exc_info()[0]))
                '''

        
        return True

    def getAndLoadProjectVersionIssuesHidden(self, id, elasticUrl):

        es = elasticUtil(elasticUrl)

        _issues = {'data': [], 'count': 0}
        
        _url = 'https://fortify.1dc.com/ssc/api/v1/projectVersions/{}/issues?start=0&limit=500&showhidden=true&showremoved=true&showsuppressed=true&showshortfilenames=true'.format(id)

        _moreRecords = True

        iCurrentRecord = 0

        while _moreRecords:

            response = requests.get(_url, auth=HTTPBasicAuth(self.sscUser, self.sscPassword), headers=self.headers)
            issues = json.loads(response.text)

            
            if _issues['count'] == 0:
                _issues['count'] = issues['count']
                logging.info('Downloading for {} issues'.format(_issues['count']))
            else:
                logging.info('Downloading at {} - {} of {} total records'.format(iCurrentRecord, len(issues['data']), _issues['count']))

            for issue in issues['data']:
                iCurrentRecord = iCurrentRecord + 1

                #logging.info(issue)

                if (issue['hidden'] == True):
                    
                    es.postSSCProjIssuesHidden(json.dumps(issue))
                #_issues['data'].append(issue)
                                   
            try:
                _url = issues['links']['next']['href']
        
            except KeyError:
                _moreRecords = False
                logging.info('no more records to download')
            except:
                _moreRecords = False
                logging.info('something else happened trying to get next href')
                '''print('In getProjectVersionIssues - Unexpected error:{}'.format(sys.exc_info()[0]))
                '''

        
        return True

    def getAndLoadProjectVersionIssuesHold(self, id, elasticUrl):

        es = elasticUtil(elasticUrl)

        _issues = {'data': [], 'count': 0}
        
        _url = 'https://fortify.1dc.com/ssc/api/v1/projectVersions/{}/issues?start=0&limit=500&showhidden=true&showremoved=true&showsuppressed=true&showshortfilenames=true'.format(id)

        _moreRecords = True

        iCurrentRecord = 0

        while _moreRecords:

            response = requests.get(_url, auth=HTTPBasicAuth(self.sscUser, self.sscPassword), headers=self.headers)
            issues = json.loads(response.text)

            if _issues['count'] == 0:
                _issues['count'] = issues['count']
                logging.info('Downloading for {} issues'.format(_issues['count']))
            else:
                logging.info('Downloading at {} - {} of {} total records'.format(iCurrentRecord, len(issues['data']), _issues['count']))

            for issue in issues['data']:
                iCurrentRecord = iCurrentRecord + 1
                es.postSSCProjIssues(json.dumps(issue))
                #_issues['data'].append(issue)
                                   
            try:
                _url = issues['links']['next']['href']
        
            except KeyError:
                _moreRecords = False
                logging.info('no more records to download')
            except:
                _moreRecords = False
                logging.info('something else happened trying to get next href')
                '''print('In getProjectVersionIssues - Unexpected error:{}'.format(sys.exc_info()[0]))
                '''

        
        return True

    

    def getProjectVersions(self):

        _url = 'https://fortify.1dc.com/ssc/api/v1/projectVersions?start=0&limit=200&fulltextsearch=false&includeInactive=false&fields=project,id,issueTemplateId,currentState,name'

        _moreRecords = True

        while _moreRecords:
    
            response = requests.get(_url, auth=HTTPBasicAuth(self.sscUser, self.sscPassword), headers=self.headers)
            projectVersions = json.loads(response.text)

            if self.projectVersions['count'] == 0:
                self.projectVersions['count'] = projectVersions['count']
                logging.info('Downloading for {} project versions'.format(self.projectVersions['count']))

            else:       
                logging.info('Downloading {} of {} total records'.format(len(projectVersions['data']), self.projectVersions['count']))

            for projectVersion in projectVersions['data']:
                self.projectVersions['data'].append(projectVersion)

            try:
                _url = projectVersions['links']['next']['href']
        
            except KeyError:
                _moreRecords = False
            except:
                logging.error('Unexpected error:{}'.format(sys.exc_info()[0]))
                _moreRecords = False

        logging.info('Downloaded total of {} project versions'.format(len(self.projectVersions['data'])))
        return self.projectVersions


    def fixComma(self,instr):
        sT = '{}'.format(instr).replace(',', ' ')
        return sT

    def exportSSCSummaryStats(self):
        '''
        


        '''

        ofile = open('summaryExport.csv', 'w+')

        ofile.write("ProjectID, ProjectName, VersionID, VersionName, lastFprUploadDate, issueTemplateId, Critical, High, Medium, Low\n") 
        for projectVersion in self.projectVersions['data']:

            Critical = 0
            High = 0
            Medium = 0
            Low = 0


            for issue in self.allIssues['data']:
                if issue['projectVersionID'] == projectVersion['id']:
                    Critical = issue['Critical']
                    High = issue['High']
                    Medium = issue['Medium']
                    Low = issue['Low']
                

            
            ofile.write("{}, {}, {}, {}, {}, {}, {}, {}, {}, {}\n".format(
                projectVersion['project']['id'],
                self.fixComma(projectVersion['project']['name']),
                projectVersion['id'],
                self.fixComma(projectVersion['name']),
                projectVersion['currentState']['lastFprUploadDate'],
                projectVersion['issueTemplateId'],
                Critical, High, Medium, Low))
        ofile.close()

        logging.info('Data export complete.')




        
        
      
      




 
