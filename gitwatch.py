#! /usr/bin/env python
'''
Module written to watch a git hub repo for commits and to
pull the latest changes down.

'''

import requests
import datetime
from requests.auth import HTTPBasicAuth
import git
from git import Repo
import os


class yaraUpdate:

    def __init__(self, apiToken=None, repo=None, yaraSigs=None, serverURL=None):

        today = datetime.date.today()
        self.token = apiToken
        self.repo = repo
        self.yaraDir = yaraSigs
		self.baseURL = serverURL + 'api/v3/repos/'
        self.date = str(today) + 'T00:00:00Z'

        if not os.path.exists(self.yaraDir + '.git'):

            repoUrl = 'https://' + self.token + '@' + serverURL + self.repo + '.git'
            Repo.clone_from(repoUrl, self.yaraDir)

    def chkUpdate(self):
        
        url = self.baseURL + self.repo + '/commits?since=' + self.date + '&access_token=' + self.token
 
        r = requests.get(url)

        if(r.status_code == 401):

            print "Bad Token"
        
        elif(r.status_code == 200):

            if(r.text != '[]'):

                updateData = r.json()

                self.date = updateData[0]['commit']['committer']['date']
                dt = parser.parse(self.date)
                dt = str(dt + datetime.timedelta(0,1))
                dt = dt.replace(" ", "T")
                self.date = dt.replace('+00:00', 'Z')

                return('update')
        else:

            print "Error " + str(r.status_code)

    def gitClone(self):

        g = git.cmd.Git(self.yaraDir)
        g.pull()
        
