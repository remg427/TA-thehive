#!/usr/bin/python
#
# Extract IOC's from thehive
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made

import splunk.admin as admin
# import your required python modules
import os
import csv
import logging

'''
Copyright (C) 2005 - 2010 Splunk Inc. All Rights Reserved.
Description:  This skeleton python script handles the parameters in the configuration page.

      handleList method: lists configurable parameters in the configuration page
      corresponds to handleractions = list in restmap.conf

      handleEdit method: controls the parameters and saves the values
      corresponds to handleractions = edit in restmap.conf

'''

__author__     = "Remi Seguy"
__license__    = "LGPLv3"
__version__    = "1.03"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"


class ConfigApp(admin.MConfigHandler):
  '''
  Set up supported arguments
  '''
  def setup(self):
    if self.requestedAction == admin.ACTION_EDIT:
      for arg in ['thehive_url', 'thehive_key', 'thehive_verifycert', 'thehive_use_proxy', 'http_proxy', 'https_proxy']:
        self.supportedArgs.addOptArg(arg)

  '''
  Read the initial values of the parameters from the custom file
      thehive.conf, and write them to the setup page.

  If the app has never been set up,
      uses .../app_name/default/thehive.conf.

  If app has been set up, looks at
      .../local/thehive.conf first, then looks at
      .../default/thehive.conf only if there is no value for a field in .../local/thehive.conf

  For boolean fields, may need to switch the true/false setting.

  For text fields, if the conf file says None, set to the empty string.
  '''

  def handleList(self, confInfo):
    confDict = self.readConf("thehive")
    if None != confDict:
      for stanza, settings in confDict.items():
        for key, val in settings.items():
          if key in [ 'thehive_use_proxy','thehive_verifycert']:
            if int(val) == 1:
              val = '1'
            else:
              val = '0'
          if key in ['thehive_url', 'thehive_key', 'http_proxy', 'https_proxy'] and val in [None, '']:
            val = ''
          confInfo[stanza].append(key, val)

  '''
  After user clicks Save on setup page, take updated parameters,
  normalize them, and save them somewhere
  '''
  def handleEdit(self, confInfo):
    # set up logging suitable for splunkd consumption
    logging.root
    logging.root.setLevel(logging.ERROR)

    if int(self.callerArgs.data['thehive_verifycert'][0]) == 1:
      self.callerArgs.data['thehive_verifycert'][0] = '1'
      thehive_verifycert = True
    else:
      self.callerArgs.data['thehive_verifycert'][0] = '0'
      thehive_verifycert = False
    if int(self.callerArgs.data['thehive_use_proxy'][0]) == 1:
      self.callerArgs.data['thehive_use_proxy'][0] = '1'
      thehive_use_proxy = True
    else:
      self.callerArgs.data['thehive_use_proxy'][0] = '0'
      thehive_use_proxy = False
    if self.callerArgs.data['thehive_url'][0] in [None, '']:
      self.callerArgs.data['thehive_url'][0] = ''
    if self.callerArgs.data['thehive_key'][0] in [None, '']:
      self.callerArgs.data['thehive_key'][0] = ''
    if self.callerArgs.data['http_proxy'][0] in [None, '']:
      self.callerArgs.data['http_proxy'][0] = ''
    if self.callerArgs.data['https_proxy'][0] in [None, '']:
      self.callerArgs.data['https_proxy'][0] = ''

#    Since we are using a conf file to store parameters,
#    write them to the [thehivesetup] stanza
#    in app_name/local/thehive.conf

    self.writeConf('thehive', 'thehivesetup', self.callerArgs.data)
#   Write also parameters under misp42splunk/lookups/thehive_instances.csv
#   header row: thehive_instance,thehive_url,thehive_key,thehive_verifycert,thehive_use_proxy,description
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    thehive_instances = _SPLUNK_PATH + os.sep + 'etc' + os.sep + 'apps' + os.sep + 'TA-thehive' + os.sep + 'lookups' + os.sep + 'thehive_instances.csv'
    try:
        with open(thehive_instances, 'rb') as file_object:  # open thehive_instances.csv if exists and load content.
            csv_reader = csv.reader(file_object)
            header_row = next(csv_reader)
            instances = []
            for row in csv_reader:
              if 'default' in row:
                instances.append(['default', self.callerArgs.data['thehive_url'][0], self.callerArgs.data['thehive_key'][0], thehive_verifycert, thehive_use_proxy, 'default TheHive instance'])
              else:
                instances.append(row)
    except IOError : # file thehive_instances.csv doesn't exists so create empty instances
        header_row = ['thehive_instance','thehive_url','thehive_key','thehive_verifycert','thehive_use_proxy','description']
        instance = ['default', self.callerArgs.data['thehive_url'][0], self.callerArgs.data['thehive_key'][0], thehive_verifycert, thehive_use_proxy, 'default TheHive instance']
        instances = []
        instances.append(instance)

    # overwrite to the file
    try:
        with open(thehive_instances, 'wb') as file_object:  # open thehive_instances.csv if exists and load content.
            csv_writer = csv.writer(file_object, delimiter=',')
            csv_writer.writerow(header_row)
            for instance in instances:
              csv_writer.writerow(instance)
    except IOError : # file thehive_instances.csv doesn't exists so create empty instances
      logging.error("FATAL %s could not be opened in write mode", thehive_instances)

# initialize the handler
admin.init(ConfigApp, admin.CONTEXT_NONE)
