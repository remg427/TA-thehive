
# encoding = utf-8

import csv
import os
import re

'''
    IMPORTANT
    Edit only the validate_input and collect_events functions.
    Do not edit any other part in this file.
    This file is generated only once when creating the modular input.
'''
'''
# For advanced users, if you want to create single instance mod input, uncomment this method.
def use_single_instance_mode():
    return True
'''

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    # This example accesses the modular input variable
    # thehive_url = definition.parameters.get('thehive_url', None)
    # thehive_key = definition.parameters.get('thehive_key', None)
    # thehive_verifycert = definition.parameters.get('thehive_verifycert', None)
    # thehive_use_proxy = definition.parameters.get('thehive_use_proxy', None)
    # client_use_cert = definition.parameters.get('client_use_cert', None)
    # client_cert_full_path = definition.parameters.get('client_cert_full_path', None)

    # if it does not exist, create thehive_observables.csv
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    directory = _SPLUNK_PATH + os.sep + 'etc' + os.sep + 'apps' \
        + os.sep + 'TA-thehive' + os.sep + 'lookups'
    thehive_datatypes = directory + os.sep + 'thehive_datatypes_v2.csv'
    if not os.path.exists(thehive_datatypes):
        # file thehive_datatypes_v2.csv doesn't exist. Create the file
        observables = [['field_name', 'datatype', 'regex', 'description'],
                       ['autonomous-system', 'autonomous-system', '', ''],
                       ['domain', 'domain', '', ''],
                       ['filename', 'filename', '', ''],
                       ['fqdn', 'fqdn', '', ''],
                       ['hash', 'hash', '', ''],
                       ['ip', 'ip', '', ''],
                       ['mail', 'mail', '', ''],
                       ['mail_subject', 'mail_subject', '', ''],
                       ['other', 'other', '', ''],
                       ['regexp', 'regexp', '', ''],
                       ['registry', 'registry', '', ''],
                       ['uri_path', 'uri_path', '', ''],
                       ['url', 'url', '', ''],
                       ['user-agent', 'user-agent', '', '']
                       ]
        try:
            if not os.path.exists(directory):
                os.makedirs(directory)
            with open(thehive_datatypes, 'wb') as file_object:
                csv_writer = csv.writer(file_object, delimiter=',')
                for observable in observables:
                    csv_writer.writerow(observable)
        except IOError:
            helper.log_error("FATAL {} could not be opened in write \
                mode".format(thehive_datatypes))

    thehive_url = definition.parameters.get('thehive_url', None)
    match = re.match("^https:\/\/[0-9a-zA-Z\-\.]+(?:\:\d+)?$", thehive_url)
    if match is None:
        helper.log_error("Invalid URL. Please provide TLS URL without ending \
            / e.g. https://thehive.example.com:8080 ")
        raise Exception, "Invalid URL: %s. Please provide TLS URL without \
            ending / e.g. https://thehive.example.com:8080 " % thehive_url
    else:
        pass

def collect_events(helper, ew):
    """Implement your data collection logic here

    # The following examples get the arguments of this input.
    # Note, for single instance mod input, args will be returned as a dict.
    # For multi instance mod input, args will be returned as a single value.
    opt_thehive_url = helper.get_arg('thehive_url')
    opt_thehive_key = helper.get_arg('thehive_key')
    opt_thehive_verifycert = helper.get_arg('thehive_verifycert')
    opt_thehive_use_proxy = helper.get_arg('thehive_use_proxy')
    opt_client_use_cert = helper.get_arg('client_use_cert')
    opt_client_cert_full_path = helper.get_arg('client_cert_full_path')
    # In single instance mode, to get arguments of a particular input, use
    opt_thehive_url = helper.get_arg('thehive_url', stanza_name)
    opt_thehive_key = helper.get_arg('thehive_key', stanza_name)
    opt_thehive_verifycert = helper.get_arg('thehive_verifycert', stanza_name)
    opt_thehive_use_proxy = helper.get_arg('thehive_use_proxy', stanza_name)
    opt_client_use_cert = helper.get_arg('client_use_cert', stanza_name)
    opt_client_cert_full_path = helper.get_arg('client_cert_full_path', stanza_name)

    # get input type
    helper.get_input_type()

    # The following examples get input stanzas.
    # get all detailed input stanzas
    helper.get_input_stanza()
    # get specific input stanza with stanza name
    helper.get_input_stanza(stanza_name)
    # get all stanza names
    helper.get_input_stanza_names()

    # The following examples get options from setup page configuration.
    # get the loglevel from the setup page
    loglevel = helper.get_log_level()
    # get proxy setting configuration
    proxy_settings = helper.get_proxy()
    # get account credentials as dictionary
    account = helper.get_user_credential_by_username("username")
    account = helper.get_user_credential_by_id("account id")
    # get global variable configuration
    global_userdefined_global_var = helper.get_global_setting("userdefined_global_var")

    # The following examples show usage of logging related helper functions.
    # write to the log for this modular input using configured global log level or INFO as default
    helper.log("log message")
    # write to the log using specified log level
    helper.log_debug("log message")
    helper.log_info("log message")
    helper.log_warning("log message")
    helper.log_error("log message")
    helper.log_critical("log message")
    # set the log level for this modular input
    # (log_level can be "debug", "info", "warning", "error" or "critical", case insensitive)
    helper.set_log_level(log_level)

    # The following examples send rest requests to some endpoint.
    response = helper.send_http_request(url, method, parameters=None, payload=None,
                                        headers=None, cookies=None, verify=True, cert=None,
                                        timeout=None, use_proxy=True)
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

    # The following examples show usage of check pointing related helper functions.
    # save checkpoint
    helper.save_check_point(key, state)
    # delete checkpoint
    helper.delete_check_point(key)
    # get checkpoint
    state = helper.get_check_point(key)

    # To create a splunk event
    helper.new_event(data, time=None, host=None, index=None, source=None, sourcetype=None, done=True, unbroken=True)
    """

    '''
    # The following example writes a random number as an event. (Multi Instance Mode)
    # Use this code template by default.
    import random
    data = str(random.randint(0,100))
    event = helper.new_event(source=helper.get_input_type(), index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=data)
    ew.write_event(event)
    '''

    '''
    # The following example writes a random number as an event for each input config. (Single Instance Mode)
    # For advanced users, if you want to create single instance mod input, please use this code template.
    # Also, you need to uncomment use_single_instance_mode() above.
    import random
    input_type = helper.get_input_type()
    for stanza_name in helper.get_input_stanza_names():
        data = str(random.randint(0,100))
        event = helper.new_event(source=input_type, index=helper.get_output_index(stanza_name), sourcetype=helper.get_sourcetype(stanza_name), data=data)
        ew.write_event(event)
    '''
