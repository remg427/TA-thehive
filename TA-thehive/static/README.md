# TA-thehive

This add-on is designed to add alert action on Splunk to create alerts in The Hive

# Use Cases

Hunting in Splunk logs > saved searches in Splunk > on match create an alert on TheHive or (later) any security incident response platform of your choice.

# Usage
you may build a search returning some values for these fields (field file is not supported)

autonomous-system
domain
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

and one field to group rows. For example

## example
| eval id = md5(some common key in rows belonging to the same alert)
| rename md5 AS hash:md5
| table id, autonomous-system, domain, filename, fqdn, hash, hash:md5, ip, mail, mail_subject, other, regexp, registry, uri_path, url, user-agent

## tips

- Values may be empty for some fields; they will be dropped gracefully.
- Only one combination (dataType, data, message) is kept for the same alert.
- Multivalue fields are parsed and individual values used to create observables
- if you build a field with a name like **<valid_data_type>:<some text>** then an observable is created with the text passed as message/description. See above
- You may add any other columns, they will be passed as elements with dataType "other".