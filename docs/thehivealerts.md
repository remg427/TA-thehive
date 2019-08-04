# Alert sent to TheHive
When you create a Splunk alert, you may add an alert action to create alerts in TheHive
## collect results in Splunk
### basic search results with a column by artifact type
you may build a search returning some values with fields that are mapped (in lookup/thehive_datatypes_v2.csv) to following default datatypes.
By default, the lookup contains a mapping for thehive datatypes

    autonomous-system
    domain
    file
    filename
    fqdn
    hash
    ip
    mail
    mail_subject
    other
    regexp
    registry
    uri_path
    url
    user-agent

and one field to group rows.
For example

    | eval id = md5(some common key in rows belonging to the same alert)
    | table id, autonomous-system, domain, file, filename, fqdn, hash, ip, mail, mail_subject, other, regexp, registry, uri_path, url, user-agent

Values may be empty for some fields; they will be dropped gracefully. Only one combination (dataType, data, message) is kept for the same alert.
You may add any other columns, they will be passed as elements but only fields above are imported as observables when you create/update a case.

### advance search results with additional message
The search above produce alerts with the observable datatype and value and a static message 'observed'. If you want to provide a custom message with the artifact, simply create splunk field names using the syntax "a dataType:some text". the field name will be split on first ":" and the result will be 
{'dataType': 'a dataType', 'data': 'value', 'message': 'some text'}

You can try the following dummy search to illustrate this behaviour.

        index=_* | streamstats count as rc |where rc < 4
        |eval "ip:c2 ip of bad guys"="1.1.1."+rc 
        |eval domain="www.malicious.com" 
        |eval hash:md5="f3eef6f636a08768cc4a55f81c29f347"
        |table "ip:c2 ip of bad guys" hash:md5 domain

## create the alert action "Alert to create THEHIVE alert(s)"
Fill in fields. If value is not provided, default will be provided if needed.

* Alert overall description
    - TheHive instance: one of the instances defined in inputs.conf
    - Case Template: The case template to use for imported alerts.
    - Type: The alert type. Defaults to "alert".
    - Source: The alert source. Defaults to "splunk".
    - Unique ID: A field name that contains a unique identifier specific to the source event. You may use the field value to group artifacts under the same alert.
    - Title: The title to use for created alerts.
    - Description: The description to send with the alert.
    - Tags: Use single comma-separated string without quotes for multiple tags (ex. "badIP,spam").
    - Severity: Change the severity of the created alert.
    - TLP: Change the TLP of the created alert. Default is TLP:AMBER
    - PAP: Change the PAP of the created alert. Default is PAP:AMBER