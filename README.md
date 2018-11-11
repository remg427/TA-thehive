# TA-thehive
This add-on is designed to add alert actions on Splunk to create alerts in [The Hive](https://thehive-project.org/) alerts

# Installation
This app is designed to run on Splunk Search Head(s) on Linux plateforms
1. Download this [file](TA-thehive.tar.gz) which is the Splunk TA ( it is an archive containing the sub-directory TA-thehive)
3. Install the app on your Splunk Search Head(s): "Manage Apps" -> "Install app from file"
4. A custom endpoint has been defined so you need to restart Splunk (for later updates, you may skip this step)
5. At next logon, you should be invited to configure the app (if not go to Manage Apps > TA-thehive > Set up) 
    - provide the url to the API of your instance;
    - provide the authkey.

# Use Cases

Here some activities you may carry out more easily with this app.
## Hunting in Splunk logs
saved searches in Splunk > on match create an alert on [TheHive](https://thehive-project.org/) or (later) any security incident response platform of your choice.


# Usage
Splunk alerts to [create TheHive alerts](docs/thehivealerts.md)

# Credits
The alert_action for TheHive is inpired by [this Splunk app](https://splunkbase.splunk.com/app/3642/)

# Licence
This app TA-thehive is licensed under the GNU Lesser General Public License v3.0.
