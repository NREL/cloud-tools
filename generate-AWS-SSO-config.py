#!/usr/bin/env python

"""
Automatically fetch AWS SSO login token and generate ~/.aws/config file with user's SSO roles.
Also optionally generate ~/.aws/credentials for third-party AWS tools.

                            by Michael Bartlett
"""
import boto3
import webbrowser
import datetime
import time
import configparser
import pathlib
import json
import sys
import os
import hashlib
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed

if os.getenv('AWS_DEFAULT_PROFILE') is not None: 
  del os.environ['AWS_DEFAULT_PROFILE']  # Prevent bootstrapping issues


AWS_SSO_START_URL   = 'https://nrel-ace.awsapps.com/start#/'
AWS_SSO_GRANT_TYPE  = 'urn:ietf:params:oauth:grant-type:device_code'
AWS_SSO_CLIENT_NAME = 'aws-sso-config-generator'
AWS_DEFAULT_REGION  = 'us-west-2'

HOME = pathlib.Path.home()
AWS_CONFIG_PATH     = HOME / ".aws/config"
AWS_CREDENTIAL_PATH = HOME / ".aws/credentials"
AWS_SSO_CACHE_PATH  = HOME / ".aws/sso/cache"

sso      = boto3.client('sso',      AWS_DEFAULT_REGION)
sso_oidc = boto3.client('sso-oidc', AWS_DEFAULT_REGION)


def printerr(*args, **kwargs):
  kwargs["file"]=sys.stderr
  print(*args, **kwargs)
  sys.stderr.flush()
  
  
def warn(s, **kwargs):
  printerr(f"\033[33m{s}\033[0m", **kwargs)


def map_multithreaded(function, iterator, workers=10):
  with ThreadPoolExecutor(max_workers=workers) as pool:
    return [ future.result() for future in
             as_completed( pool.submit(function, item) for item in iterator ) ]
    
    
def display_packed(options: list):
  options = [ f"{i}) {o}" for i,o in zip(itertools.count(1), options) ]
  width, _ = os.get_terminal_size()
  longest_option = max([len(o) for o in options])
  option_width, extra_space = divmod(width, longest_option)
  option_width = option_width or 1
  gap_width = (extra_space // option_width) or 1
  gap = ' ' * gap_width
  options = [ o.ljust(longest_option) for o in options ]
  options = ('\n'.join( [ gap.join(options[i:i+option_width])
                          for i in range(0, len(options), option_width) ] ) )
  printerr(options)
  sys.stderr.flush()
  

def interactive_select(options, prompt='', choice=None):
  match = None
  warn_message = prompt
  suboptions = options
  while match is None:
    if choice is None:
      display_packed(suboptions)
      if warn_message:
        warn(warn_message)
        warn_message = ''
      choice = input("Enter selection (index or name): ")
      printerr()
    if choice.isnumeric():
      try:
        match = suboptions[int(choice)-1]
        break
      except IndexError:
        pass
    warn_message = ''
    matches = [ o for o in suboptions if choice.lower() in o.lower() ]
    if len(matches) > 1:
      submatches = [ m for m in matches if m.lower() == choice.lower() ]
      if len(submatches) == 1:
        match = submatches[0]
        break
      else:
        warn_message = f"Multiple matches for '{choice}'\n"
        suboptions = matches
    elif len(matches) < 1:
      warn_message = f"No matches for '{choice}'\n"
      suboptions = options
    else:
      match = matches[0]
      break
    choice = None
  return match


def cache_token(access_token, expiration_date, region):
  # AWS CLI hash name found from botocore.utils.SSOTokenLoader
  client_hash = hashlib.sha1(AWS_SSO_START_URL.encode('utf-8')).hexdigest()
  
  AWS_SSO_CACHE_PATH.mkdir(parents=True, exist_ok=True)
  with (AWS_SSO_CACHE_PATH / f'{client_hash}.json').open('w') as cache_file:
    cache_file.write( json.dumps( {'accessToken': access_token,
                                   'expiresAt': expiration_date,
                                   'region': region,
                                   'startUrl': AWS_SSO_START_URL} ) )


def get_access_token():
  register_client_response = sso_oidc.register_client(clientName=AWS_SSO_CLIENT_NAME,
                                                      clientType='public')
  client_id = register_client_response['clientId']
  client_secret = register_client_response['clientSecret']
  start_authorization_response = sso_oidc.start_device_authorization(clientId=client_id,
                                                                     clientSecret=client_secret,
                                                                     startUrl=AWS_SSO_START_URL)
  device_code = start_authorization_response['deviceCode']
  verification_uri = start_authorization_response['verificationUriComplete']
  
  webbrowser.open_new_tab(verification_uri)
  
  for retry in range(120):    # sso_oidc.waiter_names is an empty list so can't use .wait()
    try:
      token_response = sso_oidc.create_token(clientId      = client_id,
                                             clientSecret = client_secret,
                                             grantType    = AWS_SSO_GRANT_TYPE,
                                             deviceCode   = device_code,
                                             code         = device_code)
      break
    except sso_oidc.exceptions.AuthorizationPendingException:
      time.sleep(1)
      continue
  else:
    raise TimeoutError("Script timed out awaiting a valid access token.")
  
  access_token = token_response['accessToken']
  expiration_date = ( datetime.datetime.now(datetime.timezone.utc)
                      + datetime.timedelta(0, token_response['expiresIn']) ).isoformat()
  return access_token, expiration_date


def get_permission_sets(access_token):
  permission_sets = {}
  accounts = (sso
              .get_paginator('list_accounts')
              .paginate(accessToken=access_token)
              .build_full_result()
              ['accountList'])
              
  def _get_account_roles_thread_task(account):
    aws_account_id   = account['accountId']
    aws_account_name = account['accountName'].replace(" ", "-").lower()
    roles = (sso
            .get_paginator('list_account_roles')
            .paginate(accountId=aws_account_id, accessToken=access_token)
            .build_full_result()
            ['roleList'])
    
    account_permission_sets = {}
    
    for role in roles:
      role_name = role['roleName']
      profile_name = f"{aws_account_name}-{role_name}"
      account_permission_sets[profile_name] = { "role_name":      role_name,
                                                "aws_account_id": aws_account_id }
      printerr(f"\r\033[2K{account['accountName']} ({aws_account_id}) - {role_name}", end='')
      
    return account_permission_sets
      
    
  permission_sets = map_multithreaded(_get_account_roles_thread_task, accounts)
  printerr("\r\033[2K", end='')
  
  return { profile_name: profile_data
           for permission_set in permission_sets
           for profile_name, profile_data in permission_set.items() }
  
    
def get_permission_set_credentials(access_token, permission_sets):
  return {permission_set: sso.get_role_credentials( roleName=permission_set_data['sso_role_name'],
                                                    accountId=permission_set_data['sso_account_id'],
                                                    accessToken=access_token )['roleCredentials']
          for permission_set, permission_set_data in permission_sets.items()}
    
    
def main():
  import argparse
  parser = argparse.ArgumentParser()
  parser.add_argument("--credentials", '-c',
                      help=f"generate access keypairs for roles in {AWS_CREDENTIAL_PATH}",
                      action='store_true')
  parser.add_argument("--region", '-r',
                      type=str,
                      help=f"the AWS region to use (default is {AWS_DEFAULT_REGION})",
                      default=AWS_DEFAULT_REGION)
  parser.add_argument("--default-profile", "-p",
                      type=str,
                      help="AWS config profile to set as the default profile in [default] section")
  parser.add_argument("--default-output", "-o",
                      type=str,
                      help="default output type to use in AWS CLI config",
                      default="json",
                      dest="output",
                      choices=['json', 'text', 'table'])
  parser.add_argument("--aws-config-extras", "-x",
                      type=str,
                      help="""comma-separate 'key=value' list of extra config options to write to
                              AWS CLI config. Example:
                              cli_follow_urlparam=false,aws_cli_auto_prompt=on-partial""",
                      dest="extras")
  parser.add_argument("--force", '-f',
                      help="overwrite AWS user config files without asking",
                      action='store_true')
  args = parser.parse_args()

  if args.extras:
      args.extras = {(parts := pair.split('='))[0] : parts[1] for pair in args.extras.split(',')}
  else:
      args.extras = {}
  
  if AWS_CONFIG_PATH.exists() and not args.force:
    if input(f"{AWS_CONFIG_PATH} already exists. Overwrite? [y/N]:")[0].lower() != 'y':
      printerr(f"{AWS_CONFIG_PATH} unchanged.")
      sys.exit(1)
      
  sso.meta.config.region_name      = args.region
  sso_oidc.meta.config.region_name = args.region
      
  access_token, expiration_date = get_access_token()

  cache_token(access_token, expiration_date, args.region)
  
  permission_sets = get_permission_sets(access_token)
  
  
  if args.credentials:
    permission_set_credentials = get_permission_set_credentials(access_token, permission_sets)
    aws_credentials = configparser.ConfigParser()
    for profile_name, credentials in permission_set_credentials.items():
      aws_credentials.add_section(profile_name)
      credential_section = aws_credentials[profile_name]
      credential_section["aws_access_key_id"]     = credentials["accessKeyId"]
      credential_section["aws_secret_access_key"] = credentials["secretAccessKey"]
      credential_section["aws_session_toke n"]     = credentials["sessionToken"]
    aws_credentials.write(AWS_CREDENTIAL_PATH.open('w'))
    printerr(f"Wrote credentials to {AWS_CREDENTIAL_PATH}.")
    
  aws_config = configparser.ConfigParser()
  for profile_name, profile_data in permission_sets.items():
    section_header = f"profile {profile_name}"
    aws_config.add_section(section_header)
    profile_section = aws_config[section_header]
    profile_section['sso_start_url']  = AWS_SSO_START_URL
    profile_section['sso_account_id'] = profile_data['aws_account_id']
    profile_section['sso_role_name']  = profile_data['role_name']
    profile_section['sso_region']     = args.region
    profile_section['region']         = args.region
    profile_section['output']         = args.output
    
  default_profile = interactive_select(permission_sets.keys(),
                                       prompt='Select a default profile',
                                       choice=args.default_profile)
  warn(f"Using {default_profile} as the default AWS profile.")
  
  aws_config.add_section('default')
  aws_config['default'] = aws_config[f"profile {default_profile}"]
    
  aws_config.write(AWS_CONFIG_PATH.open('w'))
  printerr(f"Wrote SSO permission set profiles to {AWS_CONFIG_PATH}.")
  

if __name__ == '__main__':
  sys.exit(main())