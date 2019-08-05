import requests
import json
import base64



class JiraUtils:


    def __init__(self, username, password, URL, Project):
        self.jiraUser = username
        self.jiraPassword = password
        bytesToEncode = "{}:{}".format(self.jiraUser, self.jiraPassword).encode('ascii')
        self.authToken = base64.b64encode(bytesToEncode).decode('ascii')
        self.jiraURL = URL
        self.jiraProject = Project

        self.headers = {'Authorization': 'Basic {}'.format(self.authToken),
                     'Content-Type': 'application/json'}



    def getCardsInColumn(self, column):
        # Get Scanning issues from Jira

        _jpostbody = {
            "jql": "project = {} AND status = {}".format(self.jiraProject, column),
            "startAt": 0,
            "maxResults": 5000,
            "fields": ["summary", "status", "assignee", "created"]
        }

        if column == "ALL":
            _jpostbody = {
                "jql": "project = SCAN",
                "startAt": 0,
                "maxResults": 5000,
                "fields": ["summary", "status", "assignee", "created"]
            }




        jresponse = requests.post("{}{}".format(self.jiraURL, 'search/'), \
                                  data=json.dumps(_jpostbody), headers=self.headers)
        # print(jresponse.status_code)
        # print(jresponse.text)

        if jresponse.status_code != 200:
            raise Exception('Error: {} {}'.format(jresponse.status_code, jresponse.text))

        return json.loads(jresponse.text)


    def getCardDetail(self, id):

        jresponse = requests.get("{}issue/{}/".format(self.jiraURL, id), \
                                  headers=self.headers)
        if jresponse.status_code != 200:
            raise Exception('Error: {} {}'.format(jresponse.status_code, jresponse.text))
        return json.loads(jresponse.text)

    def deleteCardDetail(self, id):

        jresponse = requests.delete("{}issue/{}/".format(self.jiraURL, id), \
                                  headers=self.headers)
        if jresponse.status_code != 204:
            raise Exception('Error: {} {}'.format(jresponse.status_code, jresponse.text))
        return json.loads(jresponse.text)


    def addLabel(self, id, labelToAdd):


        payload = {
               'update': {'labels':[{'add': labelToAdd}]}
            }


        jresponse = requests.put("{}issue/{}".format(self.jiraURL, id), \
                                 headers=self.headers, data=json.dumps(payload))
        if jresponse.status_code != 204:
            print("Error Status: {}".format(jresponse.status_code))
            raise Exception('Error: {} {}'.format(jresponse.status_code, jresponse.text))
        return True
