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
		nullvalue = None
		needreset = False

		#print ('Release {} Issue {} RemovedDate {}'.format(InSSCVul['_source']['projectVersionId'], InSSCVul['_source']['id'], InSSCVul['_source']['removedDate']))

		if InSSCVul['_source']['removedDate']  != nullvalue:
			needreset = False
		else:
			needreset = True	

		if needreset == True:
		
			vulKey = '{}{}{}'.format(InSSCVul['_source']['projectVersionId'], InSSCVul['_source']['id'],InSSCVul['_source']['removedDate'])  

			if vulKey in self.sscVulns:
				#Increment existing counts
				vul = self.sscVulns[vulKey]
				#print('update')
			else:
				#vul = sscVulCount(InSSCVul['_source']['projectVersionId'])
				#print('new key')

				vul = {
					'projectVersionId': InSSCVul['_source']['projectVersionId'],
					'id': InSSCVul['_source']['id'],
					'removedDate': InSSCVul['_source']['removedDate'],
					'reccount': 0
				}

			vul['reccount'] = vul['reccount'] + 1
		
			self.sscVulns[vulKey] = vul

		            

		#print (self.sscVulns[vulKey])