#!/usr/bin/env bash
tmpdir="$(mktemp -d "${1:-/tmp/tmp}.XXXXXXXX")";
trap "rm -rf $tmpdir" EXIT;
set -o pipefail

unset AWS_DEFAULT_PROFILE

fail() { printf "\e[0;31m𐄂\e[0m $*\n" >&2; }
pass() { printf "\e[0;32m✔\e[0m $*\n" >&2; }
info() { printf "\e[0;34m$*\e[0m\n" >&2; }

__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python="$(which python)"
executable='generate-AWS-SSO-config.py'
test_file="$__dir/../$executable"
cmd="$python $test_file"
start_url_hash=837d21e37cb6a685a2511a693e43e64f04d4741d

cd $tmpdir

export HOME=$tmpdir
export AWS_DEFAULT_REGION=us-west-2
export PATH="$PWD/.local/bin:$PATH"

$cmd  --force &>/dev/null \
  && fail "No default profile should have failed" \
  || pass "No --default-profile produced an expected error"

[ -f ~/.aws/config ] \
  && fail "~/.aws/config shouldn't exist yet" \
  || pass "~/.aws/config not created on erroneous exit"
  
access_token_file="$HOME/.aws/sso/cache/$start_url_hash.json"
[ -f $access_token_file ] \
  || fail "SSO cache should exist" \
  && pass "SSO cache produced"
  
access_token=$(<$access_token_file jq -r .accessToken)

read account_id account_name <<<$(\
  aws sso list-accounts --access-token $access_token --query 'accountList[0]|[accountId,accountName]' --output text
)\
  || fail "Error fetching account info" \
  && pass "SSO token valid for getting account info"


read role_name account_id <<<$(\
  aws sso list-account-roles --access-token $access_token --account-id $account_id --query 'roleList[0]|[roleName,accountId]' --output text
) \
  || fail "Error fetching role name" \
  && pass "SSO token valid for getting role name"
  

account_name=${account_name// /-}
account_name=${account_name,,}

profile_name="$account_name-$role_name"

info "Using profile $profile_name"

$cmd  --force --default-profile $profile_name &>/dev/null \
  || fail "Error using default profile" \
  && pass "SSO config successfully generated using a default profile"
  
$cmd  --uninstall &>/dev/null \
  && fail "Permature uninstall should have thrown an error" \
  || pass "Premature uninstall produced expected error"
  
$cmd  --install &>/dev/null \
  || fail "Command could not install itself" \
  && pass "Command reported successful install"
  
[ -f ~/.local/bin/$executable ] \
  || fail "Command was not actually installed" \
  && pass "Command was actually installed"
  
[ -x ~/.local/bin/$executable ] \
  || fail "Command was not installed executably" \
  && pass "Command was installed executably"
  
$executable --force --default-profile $profile_name &>/dev/null \
  && pass "SSO config successfully generated using a default profile and \$PATH executable" \
  || fail "Error using default profile and \$PATH executable"
  
$executable --get-role-credentials --role-name $role_name --account-id $account_id &>/dev/null \
  && pass "$executable was able to fetch role credentials for $role_name in $account_id" \
  || fail "Unable to fetch role credentials for $role_name in $account_id"
  
# Set all credentials to be expired
rm -rf ~/.aws/credentials
sed -i '' "s/$(date +%Y)/1999/g" ~/.aws/cli/cache/*.json
mv ~/.aws/sso/cache/$start_url_hash.json ~/.aws/sso/cache/$start_url_hash.json.bk

aws sts get-caller-identity &>/dev/null \
  && fail "Expired credentials should have produced an error when using an AWS CLI command" \
  || pass "Expired credentials threw expected error without --install-credential-process"
  
mv ~/.aws/sso/cache/$start_url_hash.json.bk ~/.aws/sso/cache/$start_url_hash.json

$executable --force --default-profile $profile_name --install-credential-process &>/dev/null \
  && pass "Successfully created config with $executable as the credential process" \
  || fail "Unable to create config with $executable as the credential process"
  
grep 'sso_start_url' ~/.aws/config \
  && fail "--install-credential-process should result in no sso_* attributes in ~/.aws/config" \
  || pass "sso_* config attributes expectedly not in ~/.aws/config after --install-credential-process"
  
# Set all credentials to be expired
sed -i '' "s/$(date +%Y)/1999/g" ~/.aws/sso/cache/*.json ~/.aws/cli/cache/*.json

aws sts get-caller-identity &>/dev/null \
  && pass "Credential_helper avoided expired credential errors automatically" \
  || fail "Unable to run AWS command after expiring credentials, credential_process is broken"

grep $profile_name ~/.aws/credentials &>/dev/null  \
  && pass "$profile_name cached credentials found in ~/.aws/credentials after CLI command" \
  || fail "$profile_name should have cached credentials in ~/.aws/credentials but none were found"

$cmd  --uninstall &>/dev/null \
  || fail "Command should have uninstalled successfully" \
  && pass "Command reported successful uninstall"

[ -f ~/.local/bin/$executable ] \
  && fail "Command was not actually uninstalled" \
  || pass "Command was actually uninstalled"