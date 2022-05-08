# NREL Cloud Computing Tools
Software utilities for the NREL cloud computing user community.

## [generate-AWS-SSO-config.py](generate-AWS-SSO-config.py)


**This script requires the `boto3` python AWS SDK library be installed.** Install with `pip install boto3`

Python script to automatically create an AWS SSO login token and generate ~/.aws/config file with user's SSO roles. This will also optionally generate ~/.aws/credentials for third-party AWS tools.

**This script will open a new browser window or tab.** This is currently mandatory for the AD SAML authentcation protocol.

Invoke with python:
```sh
python generate-AWS-SSO-config.py --help
```

 or as an executable:
 
 ```sh
 chmod +x generate-AWS-SSO-config.py
 ./generate-AWS-SSO-config.py --help
 ```