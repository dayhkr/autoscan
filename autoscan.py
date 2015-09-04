#! /usr/bin/env python

import os
import pyinotify
import multiprocessing
import time
import cbapi
import zipfile
import re
import shutil
import sys
import logging
import logging.handlers
import socket
from gitwatch import *

debugLog = False 

hostname = socket.gethostname() 

#Setting the log destination for found signatures
logDest = '127.0.0.1'
logOut = logging.getLogger('autoscan.' + hostname)
logOut.setLevel(logging.DEBUG)

handler = logging.handlers.SysLogHandler(address=(logDest,514), facility='local3') 
formatter = logging.Formatter('%(name)s[%(process)s]: [%(levelname)s] %(message)s')
handler.setFormatter(formatter)
logOut.addHandler(handler)

#Starting inotify wather
wm = pyinotify.WatchManager()

mask = pyinotify.IN_CREATE #We only care about Creates
wtDir = '/var/cb/data/modulestore/'
tempDir = '/opt/autoscan/temp/'  #Temp locations to unzip and scan files

'''
Add process cleanups
'''

class PTmp(pyinotify.ProcessEvent):

    def __init__(self,fileQueue):

        self.fileQueue = fileQueue

    def process_IN_CREATE(self, event):

        fileQueue = self.fileQueue
        isDir = event.dir
        fileName = event.name
        filePath = event.path
        if(isDir == False):

            fileQueue.put(filePath + '/' + fileName)
            
def yara(data, jobNum):

    import yara
    alertData = {}
    #Looking for new zip files and ignore tmp files
    m = re.search('([A-F0-9]{32})\.zip', data) 

    if m:

        md5Sum = m.group(1)
		
        #Probably should make this a variable
        rules = yara.compile('/opt/autoscan/yara-sigs/rules/master.yara')
        print "Scanning file: " + data
		
        if(debugLog == True):

            logOut.debug("Scanning file: " + data)

		#Unzip the file to a temp directory
        fh = open(data, 'rb')
        z = zipfile.ZipFile(fh)
        for name in z.namelist():
            outpath = tempDir + md5Sum
            z.extract('filedata', outpath)
        fh.close()

        #Scan against our Yara Rules
        matches = rules.match(outpath + '/filedata', timeout=60)

        if(matches):

            if(debugLog == True):

                logOut.debug(matches)

			#Call the CB server api an look for where this file was seen
            servers = locHash(md5Sum)

            alertData[md5Sum] = {}
            alertData[md5Sum]['yaraMatch'] = matches
            alertData[md5Sum]['serverLst'] = servers
			#Send a syslog message about the match
            logOut.warn(alertData) 

        shutil.rmtree(outpath)

    jobNum.get()
    
    sys.exit() 

def locHash(md5Sum):

    #Set this to the Server URL
    cbUrl = '<Carbon Black Server URL>'
	
	#Get this from the Carbon Black Server
    apiToken = '<API Token>'
    
    results = []
    cb = cbapi.CbApi(cbUrl, token=apiToken, ssl_verify=False)
    data = cb.process_search(r"md5:" + md5Sum)

    for entry in data['results']:

        results.append(entry['hostname'])

    return results

def inotifyer(fileQueue):

    notifier = pyinotify.Notifier(wm, PTmp(fileQueue))

    wdd = wm.add_watch(wtDir, mask, rec=True, auto_add=True)

    while True:

        try:

            notifier.process_events()

            if notifier.check_events():

                notifier.read_events()

        except KeyboardInterrupt:

            notifier.stop()

            break

def main():

    #This section watches our Git hub repo for new Yara rules
	#then downloads them to our signature location
	#if you don't want to do this then comment out the next 3 lines
    repository = '<REPO>'

    yaraRules = yaraUpdate(apiToken='<Git Repo Token>', repo=repository, yaraSigs='<DIR To STORE UPDATES>')
    
    jobs = multiprocessing.Queue()
 
    while(True):

        status = fileQueue.empty()

        data = yaraRules.chkUpdate()

        if(data == 'update'):

            yaraRules.gitClone()


        if(status == False):

            queueSize = jobs.qsize()
            
            if(int(queueSize) <= 6):
                
                fileJob = fileQueue.get()
                j = multiprocessing.Process(target=yara, args=(fileJob, jobs))
                jobs.put('NewJob')
                j.start()   
            
            else:

                time.sleep(5)

        else:

            time.sleep(5)


if __name__ == '__main__':

    fileQueue = multiprocessing.Queue()
    p = multiprocessing.Process(target=inotifyer, args=(fileQueue,))
    p.start()

    main()

