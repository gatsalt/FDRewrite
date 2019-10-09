'''
/* Copyright (C) Saltworks Security, LLC - All Rights Reserved
* Unauthorized copying of this file, via any medium is strictly prohibited
* Proprietary and confidential
* Written by Saltworks Security, LLC  (www.saltworks.io) , 2019
*/
'''
import json
import sys
import requests


class sscVulCounts:
	def __init__(self):
		self.sscVulns = {}

	def addVul(self,InSSCVul):

		'''
		print('{}\t{}\t{}\t{}\t{}\t{}\t{}'.format(iCount, sscVul['_source']['projectVersionId'],
                vul['_source']['issueName'],
                vul['_source']['hidden'], 
                vul['_source']['suppressed'], 
                vul['_source']['removedDate'], 
                vul['_source']['scanStatus']))
		'''
		try:
			if InSSCVul['_source']['suppressed']:
				holdstatus = 'Suppressed'
		
		except KeyError:

			print(InSSCVul)

		if ((InSSCVul['_source']['friority'] == 'Critical') or (InSSCVul['_source']['friority'] == 'High') or (InSSCVul['_source']['friority'] == 'Medium') or (InSSCVul['_source']['friority'] == 'Low')):
			includeRec = True
		else:
			includeRec = False

		matchfound = False
			
		if (InSSCVul['_source']['hidden'] and includeRec == True):
			holdstatus = 'Hidden'
			matchfound = True

		if (InSSCVul['_source']['suppressed'] and includeRec == True):
			holdstatus = 'Suppressed'
			matchfound = True

			vulKey = '{}{}{}{}{}{}'.format(InSSCVul['_source']['projectVersionId'], InSSCVul['_source']['issueName'], holdstatus, InSSCVul['_source']['friority'], InSSCVul['_source']['foundDate'], InSSCVul['_source']['engineCategory'])  

			if vulKey in self.sscVulns:
				#Increment existing counts
				vul = self.sscVulns[vulKey]
				#print('update')
			else:
				#vul = sscVulCount(InSSCVul['_source']['projectVersionId'])
				
				vul = {
					'projectVersionId': InSSCVul['_source']['projectVersionId'],
					'issueName': InSSCVul['_source']['issueName'],
					'status': holdstatus,
					'friority': InSSCVul['_source']['friority'],
					'foundDate': InSSCVul['_source']['foundDate'],
					'removedDate': InSSCVul['_source']['removedDate'],
					'engineCategory': InSSCVul['_source']['engineCategory'],
					'reccount': 0
				}

			vul['reccount'] = vul['reccount'] + 1
			
			self.sscVulns[vulKey] = vul

		if (InSSCVul['_source']['removed'] and includeRec == True):
			holdstatus = 'Fixed'
			matchfound = True

			vulKey = '{}{}{}{}{}{}{}'.format(InSSCVul['_source']['projectVersionId'], InSSCVul['_source']['issueName'], holdstatus, InSSCVul['_source']['friority'], InSSCVul['_source']['foundDate'], InSSCVul['_source']['removedDate'], InSSCVul['_source']['engineCategory'])  
		

			if vulKey in self.sscVulns:
				#Increment existing counts
				vul = self.sscVulns[vulKey]
				#print('update')
			else:
				#vul = sscVulCount(InSSCVul['_source']['projectVersionId'])
				
				vul = {
					'projectVersionId': InSSCVul['_source']['projectVersionId'],
					'issueName': InSSCVul['_source']['issueName'],
					'status': holdstatus,
					'friority': InSSCVul['_source']['friority'],
					'foundDate': InSSCVul['_source']['foundDate'],
					'removedDate': InSSCVul['_source']['removedDate'],
					'engineCategory': InSSCVul['_source']['engineCategory'],
					'reccount': 0
				}

			vul['reccount'] = vul['reccount'] + 1
			
			self.sscVulns[vulKey] = vul

		if (matchfound == False and includeRec == True):
			holdstatus = 'Open'

			vulKey = '{}{}{}{}{}{}'.format(InSSCVul['_source']['projectVersionId'], InSSCVul['_source']['issueName'], holdstatus, InSSCVul['_source']['friority'], InSSCVul['_source']['foundDate'], InSSCVul['_source']['engineCategory'])  

			if vulKey in self.sscVulns:
				#Increment existing counts
				vul = self.sscVulns[vulKey]
				#print('update')
			else:
				#vul = sscVulCount(InSSCVul['_source']['projectVersionId'])
				
				vul = {
					'projectVersionId': InSSCVul['_source']['projectVersionId'],
					'issueName': InSSCVul['_source']['issueName'],
					'status': holdstatus,
					'friority': InSSCVul['_source']['friority'],
					'foundDate': InSSCVul['_source']['foundDate'],
					'removedDate': InSSCVul['_source']['removedDate'],
					'engineCategory': InSSCVul['_source']['engineCategory'],
					'reccount': 0
				}

			vul['reccount'] = vul['reccount'] + 1
			
			self.sscVulns[vulKey] = vul
	            
	def searchSSCProjectsforProjectId(self, projid):

		url = 'http://localhost:9200/sscprojects/_search'

		_Headers = {'Accept': 'application/json',
         		   'Content-Type': 'application/json'}

		_post ={
		        "query": {
		            "match_phrase": {
		                "id": projid
		            }
		        }
		    }


		response = requests.post(url, data=json.dumps(_post), headers=_Headers)

		#print(response.text)

		return  json.loads(response.text)

