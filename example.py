#! /usr/bin/env python

from gittest import *
import time


#example format for repo
#Threat/yara-sigs
repository = '<REPO>'

test = yaraUpdate(apiToken='<Git Repo Token>', repo=repository, yaraSigs='<DIR To STORE UPDATES>', serverURL='<ex. http://github.com/>')

while(1):

    data = test.chkUpdate()

    if(data == 'update'):

        test.gitClone()


    time.sleep(100)

