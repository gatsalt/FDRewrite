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
			if InSSCVul['_source']['hidden']:
				holdstatus = 'Hidden'
		
		except KeyError:

			print(InSSCVul)

			
		if InSSCVul['_source']['hidden']:
			holdstatus = 'Hidden'
		elif InSSCVul['_source']['suppressed']:
			holdstatus = 'Suppressed'
		elif InSSCVul['_source']['removed']:
			holdstatus = 'Removed'
		else:
			holdstatus = 'Open'

		if holdstatus == 'Removed':

			vulKey = '{}{}{}{}{}{}{}'.format(InSSCVul['_source']['projectVersionId'], InSSCVul['_source']['issueName'], holdstatus, InSSCVul['_source']['friority'], InSSCVul['_source']['foundDate'], InSSCVul['_source']['removedDate'], InSSCVul['_source']['engineCategory'])  
		
		else:

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

		            

		#print (self.sscVulns[vulKey])		

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

			
