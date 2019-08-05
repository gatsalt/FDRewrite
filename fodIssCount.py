import json
import sys
import requests


class fodIssCounts:
	def __init__(self):
		self.fodIsss = {}

	def addIss(self,InFODIss):

		'''
		print('{}\t{}\t{}\t{}\t{}\t{}\t{}'.format(iCount, sscVul['_source']['projectVersionId'],
                vul['_source']['issueName'],
                vul['_source']['hidden'], 
                vul['_source']['suppressed'], 
                vul['_source']['removedDate'], 
                vul['_source']['scanStatus']))
		'''
		try:
			if InFODIss['_source']['isSuppressed']:
				holdstatus = 'Suppressed'
		
		except KeyError:

			print(InFODIss)

		matchfound = False
			
		if InFODIss['_source']['isSuppressed']:
			holdstatus = 'Suppressed'
			matchfound = True
			issKey = '{}{}{}{}{}{}'.format(InFODIss['_source']['releaseId'], InFODIss['_source']['category'], holdstatus, InFODIss['_source']['severityString'], InFODIss['_source']['introducedDate'], InFODIss['_source']['scantype'])  

			if issKey in self.fodIsss:
				#Increment existing counts
				iss = self.fodIsss[issKey]
				#print('update')
			else:
				#vul = sscVulCount(InSSCVul['_source']['projectVersionId'])
				
				iss = {
					'releaseId': InFODIss['_source']['releaseId'],
					'category': InFODIss['_source']['category'],
					'status': holdstatus,
					'severityString': InFODIss['_source']['severityString'],
					'introducedDate': InFODIss['_source']['introducedDate'],
					'removedDate': '',
					'scantype': InFODIss['_source']['scantype'],
					'reccount': 0
				}

			iss['reccount'] = iss['reccount'] + 1
			
			self.fodIsss[issKey] = iss


		if InFODIss['_source']['status'] == 'Fix Validated':
			holdstatus = 'Fixed'
			matchfound = True
			issKey = '{}{}{}{}{}{}'.format(InFODIss['_source']['releaseId'], InFODIss['_source']['category'], holdstatus, InFODIss['_source']['severityString'], InFODIss['_source']['introducedDate'], InFODIss['_source']['scantype'])  

			if issKey in self.fodIsss:
				#Increment existing counts
				iss = self.fodIsss[issKey]
				#print('update')
			else:
				#vul = sscVulCount(InSSCVul['_source']['projectVersionId'])
				
				iss = {
					'releaseId': InFODIss['_source']['releaseId'],
					'category': InFODIss['_source']['category'],
					'status': holdstatus,
					'severityString': InFODIss['_source']['severityString'],
					'introducedDate': InFODIss['_source']['introducedDate'],
					'removedDate': '',
					'scantype': InFODIss['_source']['scantype'],
					'reccount': 0
				}

			iss['reccount'] = iss['reccount'] + 1
			
			self.fodIsss[issKey] = iss


		if matchfound == False :
			holdstatus = 'Open'

			issKey = '{}{}{}{}{}{}'.format(InFODIss['_source']['releaseId'], InFODIss['_source']['category'], holdstatus, InFODIss['_source']['severityString'], InFODIss['_source']['introducedDate'], InFODIss['_source']['scantype'])  

			if issKey in self.fodIsss:
				#Increment existing counts
				iss = self.fodIsss[issKey]
				#print('update')
			else:
				#vul = sscVulCount(InSSCVul['_source']['projectVersionId'])
				
				iss = {
					'releaseId': InFODIss['_source']['releaseId'],
					'category': InFODIss['_source']['category'],
					'status': holdstatus,
					'severityString': InFODIss['_source']['severityString'],
					'introducedDate': InFODIss['_source']['introducedDate'],
					'removedDate': '',
					'scantype': InFODIss['_source']['scantype'],
					'reccount': 0
				}

			iss['reccount'] = iss['reccount'] + 1
			
			self.fodIsss[issKey] = iss
		            

				

	def searchFODReleasesforReleaseId(self, releaseid):

		url = 'http://localhost:9200/fodreleases/_search'

		_Headers = {'Accept': 'application/json',
         		   'Content-Type': 'application/json'}

		_post ={
			"query": {
				"match_phrase": {
					"releaseId": releaseid
					}
				}
			}


		response = requests.post(url, data=json.dumps(_post), headers=_Headers)

		#print(response.text)

		return  json.loads(response.text)
			
	