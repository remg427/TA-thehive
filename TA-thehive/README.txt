This is an add-on powered by the Splunk Add-on Builder.
It is designed to add alert action on Splunk to create alerts in [The Hive](https://thehive-project.org/)

# Installation
This app is designed to run on Splunk Search Head(s) on Linux plateforms
1. Download TA-thehive.tar.gz
2. Install the app on your Splunk Search Head(s): "Manage Apps" -> "Install app from file"
3. Restart Splunk (for later updates, you may skip this step)
4. At next logon, launch the app (Manage Apps > TA-thehive > launch app)
5. create at least one input for example "default_th". Please note that mandatory fields "intervals" and "index" are not used. Just put a valid value in those ones.
    - provide a name
    - for intervals you may put 8640000 (100 days) or any other value
    - provide the url to your TH instance, ( /api/alert will be added to it to reach the endpoint)
    - provide the authkey,
    - check (or not) the certificate of the TheHive server,
    - use (or not) the proxy for this instance,
    - provide client certificate if required (and check the box to use it)
6. Parameters are saved under TA-thehive/local/inputs.conf
7. Important: Role(s)/user(s) using this app must have the capability to "list_storage_passwords" (as API KEYs and proxy password(s) are safely stored encrypted )
8. In addition, a CSV file is saved under **lookups/thehive_datatypes_v2.csv**. It contains a mapping between field names and datatypes
	- standard datatypes are included at first configuration of the app
	- then you can defined additional field (from datamodel) mapping to datatype e.g. on Splunk field _src_ (from datamodel Web) can be mapped to datatype _ip_, _dest_ to _domain_ etc. (in versions 1.x, filed name had to match datatypes)
9. This lookup can be edited to add custom datatypes in the same way.