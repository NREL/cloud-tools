# NREL Cloud Computing Tools
Software utilities for the NREL cloud computing user community.

## [aws-sso-tool](aws-sso-tool)


- **This script requires the `boto3` python AWS SDK library be installed.** Install with `pip install boto3`
- **This script will open a new browser window or tab.** This is currently mandatory for the AD SAML authentication protocol.
- **This script has only been tested on macOS.**

Python script to help automate the AWS SSO CLI experience. It can automatically create an AWS SSO login token and generate ~/.aws/config file with user's SSO roles, as well as fetch credentials for a user's permission sets interactively.


Invoke with python:
```
python aws-sso-tool --help
```

 or as an executable:
 
 ```
 chmod +x aws-sso-tool
 ./aws-sso-tool --help
 ```
 
Install the script to $PATH to invoke by name without a directory path:
 ```
$ ./aws-sso-tool --install
Installed aws-sso-tool to ~/.local/bin/aws-sso-tool

This script can now be executed with just the command:
        aws-sso-tool
        
$ aws-sso-tool --help
```

And uninstall as desired:
```
$ aws-sso-tool --uninstall
Deleted ~/.local/bin/aws-sso-tool, aws-sso-tool is no longer in $PATH.
```

### Basic Usage

#### Generate ~/.aws/config with basic SSO support

Basic SSO support enables the user to run `aws sso login` from the terminal to initiate the SSO SAML authentication protocol in their default web browser. Users will need to run `aws sso login` frequently, **especially if they recieve an error about their AWS SSO token being expired**.
 
With no arguments the user will be prompted to interactively provide required information:

```
$ aws-sso-tool configure

~/.aws/config already exists. Overwrite? [y/N]: y

--region not provided, using default region us-west-2

1) nrel-aws-account1-Permission-Set-1        2) nrel-aws-account2-Permission-Set-1
3) nrel-aws-account2-Permission-Set-2        4) nrel-aws-account2-Permission-Set-3
5) nrel-aws-account3-Permission-Set-1
Select a default profile
Enter selection (index or search term): 3

Using nrel-aws-account2-Permission-Set-2 as the default AWS profile.
Wrote SSO permission set profiles to ~/.aws/config.
``` 
 
Alternatively the user may provide necessary information as CLI flags. The fully-defined CLI equivalent to the above session would be:

```
$ aws-sso-tool configure --region us-west-2 --default-profile nrel-aws-account2-Permission-Set-2 --force

Using nrel-aws-account2-Permission-Set-2 as the default AWS profile.
Wrote SSO permission set profiles to ~/.aws/config.
```

The user may specify the other profiles not indicated as the default profile with the `--profile` flag to the AWS CLI:
```
$ aws --profile nrel-aws-account3-Permission-Set-1 sts get-caller-identity
{
    "UserId": "AROATETYIOMLHLLLLLLLL:username@nrel.gov",
    "Account": "333333333333",
    "Arn": "arn:aws:sts::333333333333:assumed-role/AWSReservedSSO_Permission-Set-1_ffffffffffffc6ec/username@nrel.gov"
}
```

See `aws-sso-tool configure --help` for more usage information.

#### Get temporary access credentials for a permission set

To interactively get credentials simply run `aws-sso-tool get-role-credentials` or more succinctly `aws-sso-tool credentials`:

```
$ aws-sso-tool get-role-credentials --output shell
--region not provided, using default region us-west-2
Using cached SSO access token
1) nrel-aws-account1-Permission-Set-1        2) nrel-aws-account2-Permission-Set-1
3) nrel-aws-account2-Permission-Set-2        4) nrel-aws-account2-Permission-Set-3
5) nrel-aws-account3-Permission-Set-1

Select which permission set to get credentials for


Enter selection (index or search term): set-1

1) nrel-aws-account1-Permission-Set-1        2) nrel-aws-account2-Permission-Set-1
3) nrel-aws-account3-Permission-Set-1

Multiple matches for 'set-1'


Enter selection (index or search term): 2

Getting credentials for Permission-Set-1 in account 222222222222

AWS_ACCESS_KEY_ID="ASIAXXXXXXXXXXXX..."
AWS_SECRET_ACCESS_KEY="huJhXXXXXXXXXXXXXXX..."
AWS_SESSION_TOKEN="IQoJXXXXXXXXXXXXXXX..."
```

See `aws-sso-tool get-role-credentials --help` for more usage information.


### Advanced Usage

#### Use a custom browser to authenticate

By default, [`aws-sso-tool`](./aws-sso-tool) will open the authorization URL to complete logging into AWS SSO via SAML the user's default browser. The user can either provide `--no-browser` to avoid opening any browser (leaving the user to manually copy and paste the authorization URL), or the user can provide a CLI command string to the `--browser` argument and `aws-sso-tool` will execute the CLI command with the verification URL as an argument.

For example, to make `aws-sso-tool` complete the authorization in an incognito Chrome window to avoid any login caching, the user can run this on macOS:
```
$ aws-sso-tool config --browser '/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --incognito'


#### Adding profile nicknames/aliases

If you use the CLI with multiple accounts, typing out the full profile names can become tedious (even with shell completions). It's possible to instruct [`aws-sso-tool`](./aws-sso-tool) to generate nicknames for certain profiles with the `--nickname` flag to the `configure` subcommand.

`--nickname` accepts a comma-separated list of match=transform mappings of regex substitution patterns.

For example, most NREL AWS accounts begin with `nrel-aws`, so it may be redundant to have to type this token every time a profile is specified. If you want to generate a nicknamed profile for each of your permission sets without this prefix, you could run:
```
$ aws-sso-tool config --nickname 'nrel-aws-(.+)=\1'
```
Where `\1` is standard regex syntax to match the first match group within `()`. Fork example, after running this command, we can use either `nrel-aws-ace-Developers` or the alias `ace-Developers`. 

As another example, if you have access to the `Developer` pemrission set in multiple accounts and you want it to be the default for that account, you could run: 
```
$ aws-sso-tool config --nickname '(.+)-Developer=\1'
```
This would make an alias of `nrel-aws-ace` for `nrel-aws-ace-Developer`.

To specify both of these regex substitutions, you can run:
```
$ aws-sso-tool config --nickname '(.+)-Developer=\1,nrel-aws-(.+)=\1'
```


#### Install this script as the `credential_process`

Use this script as the `credential_process` option in the AWS configuration profiles.

When this script is installed as the credential_process it will:
- **automatically create a new SSO token via SAML auth if your current token expires**. The default AWS CLI behavior requires the user to run `aws sso login`
manually when this happens.
- **automatically cache and regenerate a temporary access keypair for the given AWS profile as needed in ~/.aws/cli/cache/** to avoid "expired credential" errors. The default CLI behavior would require the user to manually run `aws sso login` if they receive an expired credential error.
- **automatically cache a temporary access keypair for the given AWS profile in ~/.aws/credentials to provide traditional IAM credentials for third-party AWS tools which don't directly support AWS SSO token authentication.** The default CLI behavior does not store any credentials in ~/.aws/credentials.

In other words, this script (when installed as the `credential_process` option) will run `aws sso login` automatically on the user's behalf as needed.

**Note that with the `credential_process` option the user will no longer be able to execute `aws sso login` (it will complain about misconfigured SSO profile), but this script will handle authenticating automatically such that you should not need to run `aws sso login`.**

**Also note that these benefits also extend to the AWS SDKs and therefore any applications that use the AWS SDKs.**

Please see https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html for more information.
                              
```
$ aws-sso-tool configure --install-credential-process
```

Then examine ~/.aws/config:
```
$ head ~/.aws/config

[profile nrel-aws-account1-Permission-Set-1]
region = us-west-2
output = json
credential_process = ~/.local/bin/aws-sso-tool get-role-credentials --role-name Permission-Set-1 --account-id 111111111111

...
```
Notice this script is used as the `credential_process` command. Also notice there are no `sso_*` attributes under the profiles. This is because providing the `sso_*` attributes trigger the AWS CLI to use its built in AWS SSO authentication processes. This causes the `credential_process` command to be ignored, hence they are not included in the generated AWS config if the `--install-credential-process` flag is provided.

Now when using expired credentials, the AWS CLI will automatically renew credentials that are expired:

```sh
$ cat ~/.aws/sso/cache/837d21e37cb6a685a2511a693e43e64f04d4741d.json
{
  ...,
  "expiresAt": "1999-01-01T00:00:00Z",    # Artificially set to have expired in 1999
  ...
}

$ cat ~/.aws/cli/cache/ffffffffffffffffffffffffffffffffffffffff.json
# Cached access keypair for this specific AWS profie is also expired
{ 
  "ProviderType": "sso",
  "Credentials": {
    ...,
    "Expiration": "1999-01-01T00:00:00Z", # Artificially set to have expired in 1999
    ...
  }
}

$ date
Mon May  9 12:00:00 2022

$ aws --profile nrel-aws-account3-Permission-Set-1 sts get-caller-identity


##########    <BROWSER WINDOW OPENS TO COMPLETE SAML AUTH>    ##########

{
    "UserId": "AROATETYIOMLHLLLLLLLL:username@nrel.gov",
    "Account": "333333333333",
    "Arn": "arn:aws:sts::333333333333:assumed-role/AWSReservedSSO_Permission-Set-1_ffffffffffffc6ec/username@nrel.gov"
}
```

### Tests

Execute [.tests/test-aws-sso-tool.sh](./.tests/test-aws-sso-tool.sh)

Each line of output should start with a green checkmark, any red X's indicates the code is not working as intended.
