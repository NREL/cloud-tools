#!/usr/bin/env python

"""
Automatically fetch AWS SSO login token and generate ~/.aws/config file with user's SSO roles.
Can also optionally serve as the credential_process for AWS profiles to automatically start the
SAML auth if the user's current credentials or SSO token are expired, preventing the user from
having to run `aws sso login` after encountering an error message about expired credentials.

                                     by Michael Bartlett
"""
import boto3
import botocore
import concurrent.futures
import configparser
import datetime
import hashlib
import itertools
import json
import os
import pathlib
import shutil
import stat
import sys
import time
import webbrowser


AWS_DEFAULT_REGION  = 'us-west-2'

AWS_SSO_START_URL   = 'https://nrel-ace.awsapps.com/start#/'
AWS_SSO_GRANT_TYPE  = 'urn:ietf:params:oauth:grant-type:device_code'
AWS_SSO_CLIENT_NAME = 'aws-sso-config-generator'

  # AWS CLI client hash logic from botocore.utils.SSOTokenLoader
AWS_SSO_CLIENT_HASH = hashlib.sha1(AWS_SSO_START_URL.encode('utf-8')).hexdigest()

HOME = pathlib.Path.home()
AWS_CONFIG_PATH     = HOME / ".aws/config"
AWS_CREDENTIAL_PATH = HOME / ".aws/credentials"
AWS_SSO_CACHE_PATH  = HOME / ".aws/sso/cache"
AWS_SSO_CACHE_FILE  = AWS_SSO_CACHE_PATH / f'{AWS_SSO_CLIENT_HASH}.json'
AWS_CLI_CACHE_PATH  = HOME / ".aws/cli/cache"

CURRENT_EXECUTABLE_PATH = sys.argv[0]
EXECUTABLE_NAME = os.path.basename(CURRENT_EXECUTABLE_PATH)


""" Create a boto session with absolutely no authentication.
    This prevents an infinite authentication recursion bug if this script is used as the
    credential_process script (likely via --install-credential-process) and profile authentication
    is attempted without any existing credentials. A chicken-and-egg problem arises where the
    SSO client needs to authenticate with this script, but this script needs the SSO client to
    get a new SSO token to authenticate with. 
"""
botocore_session = botocore.session.get_session({ 'profile': ( None, ['', ''], None, None ) })
botocore_session.set_credentials('','','')
session = boto3.session.Session(botocore_session = botocore_session)

sso      = session.client('sso',      AWS_DEFAULT_REGION)
sso_oidc = session.client('sso-oidc', AWS_DEFAULT_REGION)


def printerr(*args, **kwargs):
  kwargs["file"]=sys.stderr
  print(*args, **kwargs)
  sys.stderr.flush()
  
  
def fail(s, **kwargs): printerr(f"\033[31m{s}\033[0m", **kwargs); sys.exit(1)
def warn(s, **kwargs): printerr(f"\033[33m{s}\033[0m", **kwargs)
def info(s, **kwargs): printerr(f"\033[36m{s}\033[0m", **kwargs)
def verbose(s, **kwargs): warn(s, **kwargs)


def map_multithreaded(function, iterator, workers=10):
  with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
    return [ future.result() for future in
             concurrent.futures.as_completed( pool.submit(function, item) for item in iterator ) ]
    
    
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
  

def interactive_select(options, prompt='', choice=None):
  match = None
  suboptions = options
  while match is None:
    if choice is None:
      display_packed(suboptions)
      if prompt:
        info(prompt)
        prompt = ''
      choice = input("Enter selection (index or search term): ")
      printerr()
    if choice.isnumeric():
      try:
        match = suboptions[int(choice)-1]
        break
      except IndexError:
        pass
    prompt = ''
    matches = [ o for o in suboptions if choice.lower() in o.lower() ]
    if len(matches) > 1:
      submatches = [ m for m in matches if m.lower() == choice.lower() ]
      if len(submatches) == 1:
        match = submatches[0]
        break
      else:
        prompt = f"Multiple matches for '{choice}'\n"
        suboptions = matches
    elif len(matches) < 1:
      prompt = f"No matches for '{choice}'\n"
      suboptions = options
    else:
      match = matches[0]
      break
    choice = None
  return match


def noninteractive_select(options, prompt='', choice=None):
  if choice not in options:
    fail(f"'{choice}' is not present in: {' '.join(options)}")
  else:
    return choice


def create_access_token():
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
  expiration_time = ( datetime.datetime.now(datetime.timezone.utc)
                      + datetime.timedelta(0, token_response['expiresIn']) )
  return access_token, expiration_time


def cache_access_token(access_token, expiration_time, region):
  AWS_SSO_CACHE_PATH.mkdir(parents=True, exist_ok=True)
  with AWS_SSO_CACHE_FILE.open('w') as cache_file:
    cache_file.write( json.dumps( {'accessToken': access_token,
                                   'expiresAt':   expiration_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                   'region':      region,
                                   'startUrl':    AWS_SSO_START_URL} ) )


def get_cached_access_token():
  if AWS_SSO_CACHE_FILE.exists():
    with AWS_SSO_CACHE_FILE.open('r') as cache_file:
      try:
        cache_json      = json.load(cache_file)
        access_token    = cache_json['accessToken']
        expiration_time = datetime.datetime.strptime(cache_json['expiresAt'], "%Y-%m-%dT%H:%M:%S%z")
        if datetime.datetime.now(datetime.timezone.utc) < expiration_time: # Token is not expired
          verbose("Using cached SSO access token")
          return access_token, expiration_time
        else:
          verbose("Cached SSO access token is expired")
      except json.decoder.JSONDecodeError:
        pass
  return None, None


def get_access_token(region):
  access_token, expiration_time = get_cached_access_token()
  if access_token is None:
    access_token, expiration_time = create_access_token()
    cache_access_token(access_token, expiration_time, region)
  return access_token
        

def get_profile_name(aws_account_name, role_name):
  return f"{aws_account_name.replace(' ','-').lower()}-{role_name}"


def get_permission_set_accounts(access_token):
  return (sso.get_paginator('list_accounts').paginate(accessToken=access_token)
          .build_full_result()['accountList'])

def get_permission_sets(access_token):
  permission_sets = {}
  accounts = get_permission_set_accounts(access_token)
              
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
      profile_name = get_profile_name(aws_account_name, role_name)
      account_permission_sets[profile_name] = { "role_name":      role_name,
                                                "aws_account_id": aws_account_id }
      info(f"\r\033[2K{account['accountName']} ({aws_account_id}) - {role_name}", end='')
      
    return account_permission_sets
      
    
  permission_sets = map_multithreaded(_get_account_roles_thread_task, accounts)
  printerr("\r\033[2K", end='')
  
  return { profile_name: profile_data
           for permission_set in permission_sets
           for profile_name, profile_data in permission_set.items() }


def create_permission_set_credentials(access_token, role_name, account_id):
  role_credentials = sso.get_role_credentials(roleName    = role_name,
                                              accountId   = account_id,
                                              accessToken = access_token)['roleCredentials']
  expiration_iso = (datetime.datetime
                    .utcfromtimestamp(role_credentials['expiration']/1000)
                    .strftime("%Y-%m-%dT%H:%M:%SZ"))
  return {"AccessKeyId":     role_credentials['accessKeyId'],
          "SecretAccessKey": role_credentials['secretAccessKey'],
          "SessionToken":    role_credentials['sessionToken'],
          "Expiration":      expiration_iso}


def get_permission_set_credentials_hash_key(role_name, account_id):
  # cache key logic from botocore.credentials.SSOCredentialFetcher._create_cache_key
  profile = {'startUrl': AWS_SSO_START_URL, 'roleName': role_name, 'accountId': account_id}
  profile_serialized = json.dumps(profile, sort_keys=True, separators=(',', ':'))
  return hashlib.sha1(profile_serialized.encode('utf-8')).hexdigest()
  
  
def cache_permission_set_credentials(access_token, role_name, account_id, credentials):
  profile_hash = get_permission_set_credentials_hash_key(role_name, account_id)
  profile_credentials = { "ProviderType": "sso", "Credentials": credentials }
  AWS_CLI_CACHE_PATH.mkdir(parents=True, exist_ok=True)
  aws_cli_cache_file = AWS_CLI_CACHE_PATH / f'{profile_hash}.json'
  with aws_cli_cache_file.open('w') as cache_file:
    cache_file.write(json.dumps(profile_credentials))
    
  # Also cache credentials to ~/.aws/credentials to avoid CLI tools not supporting SSO based auth
  accounts = get_permission_set_accounts(access_token)
  account = [account for account in accounts if account['accountId'] == account_id][0]
  account_name = account['accountName']
  profile_name = get_profile_name(account_name, role_name)
  aws_credentials = configparser.ConfigParser()
  aws_credentials.read(AWS_CREDENTIAL_PATH)
  if not profile_name in aws_credentials.sections():
    aws_credentials.add_section(profile_name)
  credential_section = aws_credentials[profile_name]
  credential_section["aws_access_key_id"]     = credentials["AccessKeyId"]
  credential_section["aws_secret_access_key"] = credentials["SecretAccessKey"]
  credential_section["aws_session_token"]     = credentials["SessionToken"]
  aws_credentials.write(AWS_CREDENTIAL_PATH.open('w'))
    

def get_cached_permission_set_credentials(role_name, account_id):
  profile_hash = get_permission_set_credentials_hash_key(role_name, account_id)
  aws_cli_cache_file = AWS_CLI_CACHE_PATH / f'{profile_hash}.json'
  if aws_cli_cache_file.exists():
    with aws_cli_cache_file.open('r') as cache_file:
      cache_json = json.load(cache_file)
      expiration_str = cache_json['Credentials']['Expiration']
      expiration_time = datetime.datetime.strptime(expiration_str, "%Y-%m-%dT%H:%M:%S%z")
      if datetime.datetime.now(datetime.timezone.utc) < expiration_time: # Credentials not expired
        verbose(f"Using cached credentials for {role_name} in {account_id}")
        return cache_json['Credentials']
      else:
        verbose(f"Cached credentials for {role_name} are expired")
  return None


def get_permission_set_credentials(access_token, role_name, account_id):
  credentials = get_cached_permission_set_credentials(role_name, account_id)
  if credentials is None:
    credentials = create_permission_set_credentials(access_token, role_name, account_id)
    cache_permission_set_credentials(access_token, role_name, account_id, credentials)
  return credentials


def install():
  bin_directory_suffix = '.local/bin'
  bin_directory = HOME / bin_directory_suffix
  target_executable_path = bin_directory / EXECUTABLE_NAME
  actual_executable_path = shutil.which(EXECUTABLE_NAME)
  
  if actual_executable_path is not None:     # respect existing $PATH placement
    target_executable_path = pathlib.Path(actual_executable_path)
  
  if target_executable_path.exists():
    if os.path.getmtime(CURRENT_EXECUTABLE_PATH) > os.path.getmtime(target_executable_path):
      shutil.copy(CURRENT_EXECUTABLE_PATH, target_executable_path)
      info(f"Updated {target_executable_path}")
    else:
      warn(f"{target_executable_path} is the same or newer than the version of {EXECUTABLE_NAME} "
           f"that is currently executing from {CURRENT_EXECUTABLE_PATH}\n\nNo files modified.")
    return
  else:
    bin_directory.mkdir(parents=True, exist_ok=True)
    shutil.copy(CURRENT_EXECUTABLE_PATH, target_executable_path)
    in_path = any([ pathlib.Path(path).absolute() == bin_directory.absolute()
                    for path in os.getenv('PATH').split(':') ])
    if not in_path:
      SHELLRCS = {"bash": HOME/'.bashrc', "zsh": HOME/'.zshrc', "csh": HOME/'.cshrc' }
      shell = os.getenv('SHELL')
      if shell is not None:
        shell_string = f"The current shell detected is {shell}. "
        rc_path = SHELLRCS.get(shell, HOME/'.profile')
      else:
        shell_string=''
        rc_path = HOME/'.profile'
        
      warn(f"Installed {EXECUTABLE_NAME} to {target_executable_path} but {bin_directory} is "
           "not present in the $PATH environment variable."
           f"\n\n{shell_string}Please add this command to your shell initialization file {rc_path}:"
           f"\n\nexport PATH=\"{bin_directory}:$PATH\"")
           
    else:
      info(f"Installed {EXECUTABLE_NAME} to {target_executable_path}\n\nThis script can now be "
           f"executed with just the command:\n\t{EXECUTABLE_NAME}")
      
    target_executable_path.chmod(target_executable_path.stat().st_mode | stat.S_IEXEC)
    
    
def uninstall():
  actual_executable_path = shutil.which(EXECUTABLE_NAME)
  if actual_executable_path is None:
    fail(f"{EXECUTABLE_NAME} is not in $PATH. No files modified.")
  else:
    pathlib.Path(actual_executable_path).unlink()
    info(f"Deleted {actual_executable_path}, {EXECUTABLE_NAME} is no longer in $PATH.")


def main():
  import argparse
  parser = argparse.ArgumentParser()
  parser.add_argument("--region", '-r', type=str,
                      help=f"The AWS region to use in profiles (default is {AWS_DEFAULT_REGION})")
  parser.add_argument("--default-profile", "-p", type=str,
                      help="AWS config profile to set as the default profile in [default] section")
  parser.add_argument("--default-output", "-o", type=str, default="json", dest="output",
                      help="Default output type to use in AWS CLI config (default is json)",
                      choices=['json', 'text', 'table'])
  parser.add_argument("--aws-config-extras", "-x", type=str, dest="extras",
                      help="""Comma-separate 'key=value' list of extra config options to write to
                              AWS CLI config. Example:
                              cli_follow_urlparam=false,aws_cli_auto_prompt=on-partial""")
  parser.add_argument("--force", '-f', action='store_true',
                      help="Overwrite AWS user config files without asking")
  parser.add_argument("--install", action='store_true',
                      help="""Attempt to install this script to $PATH so it can executed without
                              providing the full path of this script""")
  parser.add_argument("--uninstall", action='store_true',
                      help="""Uninstall this script from $PATH""")
  parser.add_argument("--get-role-credentials", action='store_true',
                      help="generate role credentials for the given --role-name and --acount-id")
  parser.add_argument("--role-name", "--role", type=str,
                      help="""The AWS SSO role to get credentials for
                              (required with --get-role-credentials)""")
  parser.add_argument("--account-id", "--account", type=str,
                      help="""The AWS account to get credentials for
                              (required with --get-role-credentials)""")
  parser.add_argument("--install-credential-process", action='store_true',
                      help="""Use this script as the `credential_process` option in the AWS
                              configuration profiles. This script will automatically create a new
                              SSO token via SAML auth if your current token expires, whereas the 
                              default AWS CLI behavior requires the user to run `aws sso login`
                              manually when this happens, i.e. this option will run 
                              `aws sso login` automatically if needed. See
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
                              for more information.""")
  args = parser.parse_args()
  
  if args.uninstall:
    uninstall()
    return
    
  if args.install:
    install()
    return
  
  
  noninteractive = not sys.stdout.isatty() or not os.isatty(sys.stdin.fileno())
    
  if noninteractive:
    # Output is being redirected, so only print minimal info
    global verbose
    verbose = lambda *a, **k: None
    # Script is not running interactively, so throw errors instead of prompting for input
    global interactive_select, noninteractive_select
    interactive_select = noninteractive_select

  if args.extras:
      args.extras = {(parts := pair.split('='))[0] : parts[1] for pair in args.extras.split(',')}
      verbose("Got extra profiles attributes: "
              f"{' '.join([f'{k}={v}' for k,v in args.extras.items()])}")
  else:
      args.extras = {}
      
  if args.region is None:
    verbose(f"--region not provided, using default region {AWS_DEFAULT_REGION}")
    args.region = AWS_DEFAULT_REGION
  
  sso.meta.config.region_name      = args.region
  sso_oidc.meta.config.region_name = args.region
      
  access_token = get_access_token(args.region)

  if args.get_role_credentials:
    if not args.role_name or not args.account_id:
      sts = boto3.client('sts')
      identity = sts.get_caller_identity()
      args.account_id = identity['Account']
      args.role_name = identity['Arn'].split('/')[1].split('_')[1]
      warn(f"--role-name and --account-id not provided with --get-role-credentials, using current"
           f" role {args.role_name} in account {args.account_id}")
    credentials = get_permission_set_credentials(access_token, args.role_name, args.account_id)
    credentials['Version'] = 1
    print(json.dumps(credentials))
    return
  
  
  if AWS_CONFIG_PATH.exists():
    if not args.force:
      if noninteractive:
        fail(f"{AWS_CONFIG_PATH} already exists. Please use --force or delete this file.")
      else:
        if input(f"{AWS_CONFIG_PATH} already exists. Overwrite? [y/N]: ")[0].lower() != 'y':
          printerr(f"{AWS_CONFIG_PATH} unchanged.")
          sys.exit(1)
    

  permission_sets = get_permission_sets(access_token)
    
  aws_config = configparser.ConfigParser()
  
  if args.install_credential_process:
    if shutil.which(EXECUTABLE_NAME) is None and not noninteractive:
      info(f"\n{EXECUTABLE_NAME} is not in a $PATH directory.\nIf you install this application as"
           " the credential process it is recommended you make this application executable from"
           " $PATH so the AWS CLI and SDKs can easily find and execute this application.\n")
      if input(f"Install {EXECUTABLE_NAME} to a local $PATH directory? [y/N]: ")[0].lower() == 'y':
        install()
        time.sleep(2)
  
  for profile_name, profile_data in permission_sets.items():
    section_header = f"profile {profile_name}"
    aws_config.add_section(section_header)
    profile_section = aws_config[section_header]
    profile_section['region'] = args.region
    profile_section['output'] = args.output
    
    if args.install_credential_process:
      credential_process_body = (f'{sys.executable}'
                                 f' {os.path.abspath(sys.argv[0])}'
                                  ' --get-role-credentials'
                                 f" --role-name {profile_data['role_name']}"
                                 f" --account-id {profile_data['aws_account_id']}")
      profile_section['credential_process'] = credential_process_body
      
    else:
      # sso_* profile attributes override credential_process attribute, they are mutually exclusive
      profile_section['sso_start_url']  = AWS_SSO_START_URL
      profile_section['sso_account_id'] = profile_data['aws_account_id']
      profile_section['sso_role_name']  = profile_data['role_name']
      profile_section['sso_region']     = args.region
      
    for k,v in args.extras.items():
      profile_section[k] = v
    
  
  if noninteractive and args.default_profile is None:
    fail("No default profile specified."
         " Please use --default-profile to specify any of the following profiles as default:"
         f"\n{' '.join(permission_sets.keys())}")
  
  default_profile = interactive_select(list(permission_sets.keys()),
                                       prompt='Select a default profile',
                                       choice=args.default_profile)
  verbose(f"Using {default_profile} as the default AWS profile.")
  
  aws_config.add_section('default')
  aws_config['default'] = aws_config[f"profile {default_profile}"]
    
  aws_config.write(AWS_CONFIG_PATH.open('w'))
  verbose(f"Wrote SSO permission set profiles to {AWS_CONFIG_PATH}.")
  

if __name__ == '__main__':
  sys.exit(main())