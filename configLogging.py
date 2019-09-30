
import logging
import datetime

def configLogging(settings):
	t = datetime.datetime.now()
	logFile = '{}{}.TestReportingScripts.log'.format(settings['loggingFolder'], t.strftime('%Y.%m.%d'))
	print('ExtractSSC logging to: {}'.format(logFile))
	print('to view try Get-Content -Path \"{}\" -Wait'.format(logFile))
	logging.basicConfig(level=logging.INFO,
	    filename=logFile,
	    filemode='a', 
	    format='%(asctime)s - %(levelname)s - %(message)s')
