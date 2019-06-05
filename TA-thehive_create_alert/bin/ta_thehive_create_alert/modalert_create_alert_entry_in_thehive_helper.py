
# encoding = utf-8
#!/usr/bin/env python
# Generate TheHive alerts
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made

#    autonomous-system
#    domain
#    file
#    filename
#    fqdn
#    hash
#    ip
#    mail
#    mail_subject
#    other
#    regexp
#    registry
#    uri_path
#    url
#    user-agent

# most of the code here was based on the following example on splunk custom alert actions
# http://docs.splunk.com/Documentation/Splunk/6.5.3/AdvancedDev/ModAlertsAdvancedExample

import csv
import gzip
import json
import os
import requests
import sys
import time
from splunk.clilib import cli_common as cli
#from requests.auth import HTTPBasicAuth
import logging

__author__     = "Remi Seguy"
__license__    = "LGPLv3"
__version__    = "2.0.0"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"


def prepare_config(config, filename):
    config_args = {}
    # open thehive.conf
    thehiveconf = cli.getConfStanza('thehive','thehivesetup')
    # get proxy parameters if any
    http_proxy = thehiveconf.get('http_proxy', '')
    https_proxy = thehiveconf.get('https_proxy', '')
    if http_proxy != '' and https_proxy != '':
        config_args['proxies'] = {
            "http": http_proxy,
            "https": https_proxy
        }
    else:
        config_args['proxies'] = {}
    # get the thehive_url we need to connect to thehive
    # this can be passed as params of the alert. Defaults to values set in thehive.conf  
    # get specific thehive instance if any from alert configuration
    thehive_instance = config.get('thehive_instance')
    if thehive_instance:
        logging.info("alternate thehive_instance %s", thehive_instance)

        _SPLUNK_PATH = os.environ['SPLUNK_HOME']
        thehive_instances = _SPLUNK_PATH + os.sep + 'etc' + os.sep + 'apps' + os.sep + 'TA-thehive' + os.sep + 'lookups' + os.sep + 'thehive_instances.csv'
        found_instance = False
        try:
            with open(thehive_instances, 'rb') as file_object:  # open thehive_instances.csv if exists and load content.
                csv_reader = csv.DictReader(file_object)
                for row in csv_reader:
                    if row['thehive_instance'] == thehive_instance:
                        found_instance = True
                        thehive_url = row['thehive_url']
                        thehive_key = row['thehive_key']
                        if row['thehive_verifycert'] == 'True':
                            thehive_verifycert = True
                        else:
                            thehive_verifycert = False
                        if row['thehive_use_proxy'] == 'False':
                            config_args['proxies'] = {}
                        # get client cert parameters
                        if row['client_use_cert'] == 'True':
                            config_args['client_cert_full_path'] = row['client_cert_full_path']
                        else:
                            config_args['client_cert_full_path'] = None                            
        except IOError : # file thehive_instances.csv not readable
            logging.error('file thehive_instances.csv not readable')
        if found_instance is False:
            logging.error('thehive_instance name %s not found', thehive_instance)
    else: 
        # get thehive settings stored in thehive.conf
        thehive_url = str(thehiveconf.get('thehive_url'))
        thehive_key = str(thehiveconf.get('thehive_key'))
        if int(thehiveconf.get('thehive_verifycert')) == 1:
            thehive_verifycert = True
        else:
            thehive_verifycert = False
        if int(thehiveconf.get('thehive_use_proxy')) == 0:
            config_args['proxies'] = {} 
        # get client cert parameters
        if int(thehiveconf.get('client_use_cert')) == 1:
            config_args['client_cert_full_path'] = thehiveconf.get('client_cert_full_path')
        else:
            config_args['client_cert_full_path'] = None

    # check and complement config
    config_args['thehive_url'] = thehive_url
    config_args['thehive_key'] = thehive_key
    config_args['thehive_verifycert'] = thehive_verifycert   

    # Get numeric values from alert form
    config_args['tlp'] = int(config.get('tlp'))
    config_args['severity'] = int(config.get('severity'))

    # Get string values from alert form
    myTemplate = config.get('caseTemplate')
    if myTemplate in [None, '']:
        config_args['caseTemplate'] = "default"
    else:
        config_args['caseTemplate'] = myTemplate
    myType = config.get('type')
    if myType in [None, '']:
        config_args['type'] = "alert"
    else:
        config_args['type'] = myType
    mySource =  config.get('source')
    if mySource in [None, '']:
        config_args['source'] = "splunk"
    else:
        config_args['source'] = mySource
    if not config.get('unique'): 
        config_args['unique'] = "oneEvent"
    else:
        config_args['unique'] = config.get('unique')
    if not config.get('title'):
        config_args['title'] = "notable event"
    else:
        config_args['title'] = config.get('title')
    myDescription = config.get('description')
    if myDescription in [None, '']:
        config_args['description'] = "No description provided."
    else:
        config_args['description'] =  myDescription
    myTags = config.get('tags')
    if myTags in [None, '']:
        config_args['tags'] = []
    else:
        tags = []
        tag_list = myTags.split(',')
        for tag in tag_list:
            if tag not in tags:
                tags.append(tag)
        config_args['tags'] = tags
    

    # add filename of the file containing the result of the search
    config_args['filename'] = filename
    return config_args


def create_alert(config, results):

    # iterate through each row, cleaning multivalue fields and then adding the attributes under same alert key
    # this builds the dict alerts
    # https://github.com/TheHive-Project/TheHiveDocs/tree/master/api
    dataType = []
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    thehive_datatypes = _SPLUNK_PATH + os.sep + 'etc' + os.sep + 'apps' + os.sep + 'TA-thehive' + os.sep + 'lookups' + os.sep + 'thehive_datatypes.csv'
    try:
        with open(thehive_datatypes, 'rb') as file_object:  # open thehive_datatypes.csv if exists and load content.
            csv_reader = csv.DictReader(file_object)
            for row in csv_reader:
                if 'observable' in row:
                    dataType.append(row['observable'])
    except IOError : # file thehive_instances.csv not readable
        logging.info('file thehive_datatypes.csv not readable')
    if not dataType:
        dataType = ['autonomous-system', 'domain', 'filename', 'fqdn', 'hash', 'ip', 'mail', 'mail_subject', 'other', 'regexp', 'registry', 'uri_path', 'url', 'user-agent']
    alerts = {}
    alertRef = 'SPK' + str(int(time.time()))

    description = dict()
    title = dict()
    description[alertRef] = config['description']
    title[alertRef]       = config['title']
    for row in results:
        # Splunk makes a bunch of dumb empty multivalue fields - we filter those out here 
        row = {key: value for key, value in row.iteritems() if not key.startswith("__mv_")}

        # find the field name used for a unique identifier and strip it from the row
        if config['unique'] in row:
            id = config['unique']
            sourceRef = str(row.pop(id)) # grabs that field's value and assigns it to our sourceRef 
        else:
            sourceRef = alertRef

        # check if description contains a field name instead of a string. if yes, strip it from the row and assign value to description
        if config['description'] in row:
            id = config['description']
            newDescription = str(row.pop(id)) # grabs that field's value 
            if newDescription not in [None, '']:
                description[sourceRef] = newDescription

        # check if title contains a field name instead of a string. if yes, strip it from the row and assign value to title
        if config['title'] in row:
            id = config['title']
            newTitle = str(row.pop(id)) # grabs that field's value 
            if newTitle not in [None, '']:
                title[sourceRef] = newTitle
 
        # check if the field th_msg exists and strip it from the row. The value will be used as message attached to artifacts
        if 'th_msg' in row:
            artifactMessage = str(row.pop("th_msg")) # grabs that field's value and assigns it to  
        else:
            artifactMessage = ''

        # check if artifacts have been stored for this sourceRef. If yes, retrieve them to add new ones from this row
        if sourceRef in alerts:
            alert = alerts[sourceRef]
            artifacts = list(alert["artifacts"])
        else:
            alert = {}
            artifacts = [] 
        
        # now we take those KV pairs to add to dict 
        for key, value in row.iteritems():
            if value != "":
                if ':' in key:
                    dType=key.split(':',1)
                    cKey=str(dType[0])
                    cMsg=artifactMessage + '&msg: ' + str(dType[1])
                    if cKey not in dataType:
                        cKey='other'
                        cMsg=cMsg + ' - type: ' + str(key)
                elif key in dataType:
                    cKey=key
                    cMsg=artifactMessage
                else:
                    cKey='other'
                    cMsg=artifactMessage + ' - type: ' + str(key)                   
                if '\n' in value: # was a multivalue field
                    logging.debug('value is not a simple string %s', value)
                    values = value.split('\n')
                    for val in values:
                        if val != "":
                            artifact=dict(
                            dataType=cKey,
                            data=str(val),
                            message=cMsg
                            )
                            logging.debug("new artifact is %s " % artifact)
                            if artifact not in artifacts: 
                                artifacts.append(artifact)
                else:
                    artifact=dict(
                    dataType=cKey,
                    data=str(value),
                    message=cMsg
                    )
                    logging.debug("new artifact is %s " % artifact)
                    if artifact not in artifacts: 
                        artifacts.append(artifact)
    
        if artifacts:
            alert['artifacts'] = list(artifacts)
            alerts[sourceRef] = alert

    # actually send the request to create the alert; fail gracefully
    try:
        # iterate in dict alerts to create alerts
        for srcRef, artifact_list in alerts.items():
            logging.debug("SourceRef is %s and attributes are %s" % (srcRef,  artifact_list))

            payload = json.dumps(dict(
                title = title[srcRef],
                description = description[srcRef],
                tags = config['tags'],
                severity = config['severity'],
                tlp = config['tlp'],
                type = config['type'],
                artifacts = artifact_list['artifacts'],
                source = config['source'],
                caseTemplate = config['caseTemplate'],
                sourceRef = srcRef
            ))

            # set proper headers
            url  = config['thehive_url']
            auth = config['thehive_key']
            # client cert file
            client_cert = config['client_cert_full_path']

            headers = {'Content-type': 'application/json'}
            headers['Authorization'] = 'Bearer ' + auth
            headers['Accept'] = 'application/json'

            logging.debug('DEBUG Calling url="%s" with headers %s', url, headers) 
            logging.debug('DEBUG payload=%s', payload) 
            # post alert
            response = requests.post(url, headers=headers, data=payload, verify=False, cert=client_cert, proxies=config['proxies'])
            logging.info("INFO theHive server responded with HTTP status %s", response.status_code)
            # check if status is anything other than 200; throw an exception if it is
            response.raise_for_status()
            # response is 200 by this point or we would have thrown an exception
            logging.debug("theHive server response: %s", response.json())
    
    # somehow we got a bad response code from thehive
    except requests.exceptions.HTTPError as e:
        logging.error("theHive server returned following error: %s", e) 
        
def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example sends rest requests to some endpoint
    # response is a response object in python requests library
    response = helper.send_http_request("http://www.splunk.com", "GET", parameters=None,
                                        payload=None, headers=None, cookies=None, verify=True, cert=None, timeout=None, use_proxy=True)
    # get the response headers
    r_headers = response.headers
    # get the response body as text
    r_text = response.text
    # get response body as json. If the body text is not a json string, raise a ValueError
    r_json = response.json()
    # get response cookies
    r_cookies = response.cookies
    # get redirect history
    historical_responses = response.history
    # get response status code
    r_status = response.status_code
    # check the response status, if the status is not sucessful, raise requests.HTTPError
    response.raise_for_status()


    # The following example gets and sets the log level
    helper.set_log_level(helper.log_level)

    # The following example gets the alert action parameters and prints them to the log
    th_instance = helper.get_param("th_instance")
    helper.log_info("th_instance={}".format(th_instance))

    th_case_template = helper.get_param("th_case_template")
    helper.log_info("th_case_template={}".format(th_case_template))

    th_type = helper.get_param("th_type")
    helper.log_info("th_type={}".format(th_type))

    th_source = helper.get_param("th_source")
    helper.log_info("th_source={}".format(th_source))

    th_unique_id = helper.get_param("th_unique_id")
    helper.log_info("th_unique_id={}".format(th_unique_id))

    th_title = helper.get_param("th_title")
    helper.log_info("th_title={}".format(th_title))

    th_description = helper.get_param("th_description")
    helper.log_info("th_description={}".format(th_description))

    th_tags = helper.get_param("th_tags")
    helper.log_info("th_tags={}".format(th_tags))

    th_severity = helper.get_param("th_severity")
    helper.log_info("th_severity={}".format(th_severity))

    th_tlp = helper.get_param("th_tlp")
    helper.log_info("th_tlp={}".format(th_tlp))

    th_pap = helper.get_param("th_pap")
    helper.log_info("th_pap={}".format(th_pap))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="sample_sourcetype")
    helper.addevent("world", sourcetype="sample_sourcetype")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """

    helper.log_info("Alert action create_alert_entry_in_thehive started.")

    # TODO: Implement your alert action logic here
    logging.root
    logging.root.setLevel(logging.ERROR)    
    # make sure we have the right number of arguments - more than 1; and first argument is "--execute"
    if len(sys.argv) > 1 and sys.argv[1] == "--execute":
        # read the payload from stdin as a json string
        payload = json.loads(sys.stdin.read())
        # extract the file path and alert config from the payload
        configuration = payload.get('configuration')
        filename = payload.get('results_file')
        # test if the results file exists - this should basically never fail unless we are parsing configuration incorrectly
        # example path this variable should hold: '/opt/splunk/var/run/splunk/12938718293123.121/results.csv.gz'
        if os.path.exists(filename):
            # file exists - try to open it; fail gracefully
            try:
                # open the file with gzip lib, start making alerts
                # can with statements fail gracefully??
                with gzip.open(filename) as file:
                    # DictReader lets us grab the first row as a header row and other lines will read as a dict mapping the header to the value
                    # instead of reading the first line with a regular csv reader and zipping the dict manually later
                    # at least, in theory
                    Reader = csv.DictReader(file)
                    logging.debug('Reader is %s', str(Reader))
                    logging.debug("Creating alert with config %s", json.dumps(configuration))
                    Config = prepare_config(configuration,filename)
                    logging.debug('Config is %s', json.dumps(Config))
                    # make the alert with predefined function; fail gracefully
                    create_alert(Config, Reader)
                # by this point - all alerts should have been created with all necessary observables attached to each one
                # we can gracefully exit now
                sys.exit(0)
            # something went wrong with opening the results file
            except IOError as e:
                logging.error("FATAL Results file exists but could not be opened/read")
                sys.exit(3)
        # somehow the results file does not exist
        else:
            logging.error("FATAL Results file does not exist")
            sys.exit(2)
    # somehow we received the wrong number of arguments
    else:
        logging.error("FATAL Unsupported execution mode (expected --execute flag)")
        sys.exit(1)

    return 0
