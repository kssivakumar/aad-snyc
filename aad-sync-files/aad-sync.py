#! /usr/bin/env python3
from python_http_client import HTTPError

import os
import sys
import json
import urllib.parse
import urllib.request
import urllib.error
import re
import random
import string
import hashlib
import subprocess
import sendgrid

### Globals
## Config variables that are static and not sensitive
# password_length (int): Character length of generated passwords
# user_uid_low (int): User UID that sync users will be started at
# user_uid_high (int): User UID that is the end of sync users to manage

password_length = 16
user_uid_low = 2000
user_uid_high = 2999

### Managed functions
## Functions that are manage the activities of the application
def get_config():
  '''
  Collects config details for authentication to Azure using the environment variable
  AUTH_JSON. 

  Parameters:
    None

  Returns:
    dict(
      'client_id':<ID>,
      'client_sectret':<SECRET>,
      'tenant_id':<ID>,
      'auth_group':<ID>,
      'account_use':<HOST NAME>,
      'user_environment':<ENV>
      'aad_domain':<ENV_DOMAIN>
    )

  Exceptions:
    None
  '''
  data = None
  if 'AUTH_JSON' in dict(os.environ).keys():
    with open(os.environ['AUTH_JSON']) as json_file:
      data = json.load(json_file)

  return dict(data)

def get_token(config):
  '''
  Makes REST call to login.microsoftonline.com to get Oauth2 token for authentication
  to Microsoft Graph.

  Parameters:
    config (dict): configuration dict from get_config()

  Returns:
    access_token (str): Access token

  Exceptions:
    urllib.error.HTTPError: Error with REST API call
  '''
  url_params = {
    'client_id': config['client_id'],
    'client_secret': config['client_secret'],
    'grant_type': 'client_credentials',
    'scope': 'https://graph.microsoft.com/.default'
  }

  url_path = 'https://login.microsoftonline.com/%s/oauth2/v2.0/token' % (config['tenant_id'])

  req = urllib.request.Request(
          url = url_path,
          data = urllib.parse.urlencode(url_params).encode(),
  )

  req.add_header('Content-Type', 'application/x-www-form-urlencoded')
  req.add_header('Host', 'login.microsoftonline.com')
  req.add_header('Content-Length', len(urllib.parse.urlencode(url_params)))

  try:
    res = urllib.request.urlopen(req)
    res_body = res.read()
    json_data = json.loads(res_body.decode())
    return json_data['access_token']
  except urllib.error.HTTPError as e:
      print('Get Token Failed: %s' % (e.fp.read()))
      sys.exit(1)

def get_group_members(group_id, token):
  '''
  Make a REST call to Microsoft Graph to get members of the nominated group to sync users from. 

  Parameters: 
    group_id (str): Object ID of AAD group to sync users from. Managed in env variable AUTH_JSON
    token (str): Oauth2 token for API calls. Generated in get_token()

  Returns:
   res_body (dict): Dictionary of JSON response containg the users to sync
  
  Exceptions:
    urllib.error.HTTPError: Error with REST API call
  '''
  url_params = {}

  url_path = 'https://graph.microsoft.com/v1.0/groups/%s/members' % (group_id)

  req = urllib.request.Request(
          url = url_path,
  )

  req.add_header('Authorization', 'Bearer %s' % (token))

  try:
    res = urllib.request.urlopen(req)
    if res.status == 200:
      res_body = res.read()
      return json.loads(res_body.decode())
    else:
      return res_body
  except urllib.error.HTTPError as e:
    print('Get Users: %s' % (e.fp.read()))
    sys.exit(1)

def validate_users(environment, aad_domain, group_members):
  '''
  Validates users to ensure that the correct users from the group are sync'd to the host. Function
  also identifies and sets the Linux user (key: linuxUser) in the users record (dict).

  Parameters:
    environment (str): Environment prefix for users to be sync'd. Supplied by user_environment in env var in AUTH_JSON
    aad_domain (str): Domain URL for the AAD domain. Supplied by Global aad_domain
    group menbers (dict): Dictionary of the users in the AAD group. Return value of get_group_members()

  Returns:
    valid_users (list): List of valid user records (dict) with linuxUser set readu for create/delete actions
  
  Exceptions:
    Exception("Environment must be npd or prd. %s was given" % (environment))

  '''
  expr =''
  
  if environment == 'prd':
    expr = '(?P<user>[a-zA-Z\-]+)@(?P<domain>%s)' % (aad_domain)
  elif environment == 'npd':
    expr = '(?P<user>%s-[a-zA-Z\-]+)@(?P<domain>%s)' % (environment, aad_domain)
  else:
    raise Exception("Environment must be npd or prd. %s was given" % (environment))
  
  regex = re.compile(expr)

  valid_users = []

  for aad_user in group_members['value']:
    regex_match = regex.match(aad_user['userPrincipalName'])
    if regex_match:
      user_dict = regex_match.groupdict()
      aad_user['linuxUser'] = user_dict['user']

      valid_users.append(aad_user)

  return valid_users

def create_user(user, passwd, uid):
  '''
  Manages the *nix commands required to creat a user on the system.

  Parameters:
    user (str): The user name to be created. From linuxUser in the user record dict
    passwd (str): Temp passwd for the user to be created. Is generated by create_passwd()
    uid (str): The assisgned user ID for the user

  Returns:
    None

  Exceptions:
    None
  '''
  # Setup commands to creat user
  print('%s, %s' % (user, uid))
  user_create = '/usr/sbin/useradd -d /home/%s -m --system -u %s %s' % (user, uid, user)
  passwd_str = 'echo \'%s\n%s\' | passwd %s' % (passwd, passwd, user)
  passwd_expire = 'passwd -e %s' % (user)

  # Create User
  create_result = subprocess.getoutput(user_create)
  print('User CMD::: %s' % create_result)
  passwd_result = subprocess.getoutput(passwd_str)
  print('Passwd CMD::: %s' % passwd_result)
  expire_result = subprocess.getoutput(passwd_expire)
  print('Expire CMD::: %s' % expire_result)

def delete_user(user):
  '''
  Manages the *nix commands required to delete user and remove home directory.

  Parameters:
    user (str): Username of the user to be deleted

  Returns: 
    None

  Exceptions:
    None
  '''
  # Setup command to delete user
  user_delete = '/usr/sbin/userdel %s' % (user)
  rm_home = 'rm -Rf /home/%s' % (user)

  # Delete User
  delete_result = subprocess.getoutput(user_delete)
  print('Delete CMD::: %s' % delete_result)
  homedir_result = subprocess.getoutput(rm_home)
  print('Homedir CMD::: %s' % homedir_result)

def user_management(uid_low, uid_high, user_list):
  '''
  Orchestration function of user management actions based on the state of the group members
  returned by get_group_members(). This includes user creation, deletion and dependant 
  functions.

  Parameters: 
    uid_low (int): UID value where the AAD sync users will start their creation
    uid_high (int): UID value that is the end of the AAD ync users bracket
    user_list (list): List containing validated user records (dict). values supplied by validate_users()

  Returns:
    List of newly created users

  Exceptions:
    None
  '''
  # Create
  passwd_users = {}
  with open('/etc/passwd', 'r') as f:
    for line in f.readlines():
      if not line[0] == '#':
        split_line = line.split(':')
        if int(split_line[2]) in list(range(int(uid_low),int(uid_high)+1)):
          passwd_users[split_line[0]] = split_line

  # Regex to check if AAD-Sync user has Email set
  EMAIL_REGEX = re.compile('[^@]+@[^@]+\.[^@]+')

  # List of newly create users
  new_users = []

  for user in user_list:
    if (not user['linuxUser'] in passwd_users) and (EMAIL_REGEX.match(str(user['mail']))):
      print('Create user: %s:%s' % (user['linuxUser'], user['linuxPasswd']))
      user_uid = new_uid(passwd_users, uid_low)
      create_user(user['linuxUser'], user['linuxPasswd'], user_uid)
      passwd_users[user['linuxUser']] = ['', '', user_uid]
      new_users.append(user)
    if not EMAIL_REGEX.match(str(user['mail'])):
      print('User %s has no appropriate Email set' % (user['userPrincipalName']))

  # Delete
  aad_users = [ u['linuxUser'] for u in user_list ]
  for user in passwd_users.keys():
    if not user in aad_users:
      print('Delete user: %s' % user)
      delete_user(user)

  return new_users

def create_passwd(passwd_len, group_members):
  '''
  Creates a random generated passwordusing random characters from a SHA512 hash that has been salted by
  the users Azure Object ID that is supplied as part of the user record dict from validated_users. The passowrd 
  is added to the user record dict in the key linuxPasswd.

  Parameters:
    passwd_len (int): Numbber of characters the password should be made up of. Managed in Global password_length
    group_members (list): List of validated user records (dict). These are suppled from validate_users()

  Returns:
    group_members (list): List of user records with password added to key linuxPasswd

  Exceptions:
    None
  '''
  for aad_user in group_members:
    passwd_approved = False

    passwd = ''
    while not(passwd_approved):
      passwd_material = hashlib.sha512(aad_user['id'].encode('ascii')).hexdigest()
      other_material = ['!','@','#','$','%','^','&','*','(',')']
      random.shuffle(other_material)

      for num in range(1,int(passwd_len)+1):
          passwd += passwd_material[random.randint(0,len(passwd_material)-1)]

      str_pos = random.randint(0,len(passwd)-1)
      ochr_pos = random.randint(0,len(other_material)-1)

      passwd = passwd[:str_pos] + other_material[ochr_pos] + passwd[str_pos+1:]

      str_pos = random.randint(0,len(passwd)-1)
      passwd = passwd[:str_pos] + random.choice(string.ascii_uppercase) + passwd[str_pos+1:]

      if any(chr.isupper() for chr in passwd) and any(chr.islower() for chr in passwd) and any(chr in passwd for chr in other_material):
        passwd_approved = True

    aad_user['linuxPasswd'] = passwd

  return group_members

def new_uid(users, start_uid):
  '''
  Locates the first available UID within the UID block to ensure efficent use of the UID space.

  Parameters:
    users (list): List of existing users that exist on the host and are in the UID bracket for AAD sync users.
    start_uid (int): The start ID of the AAD sync users bracket

  Returns:
    new_uid (int): First available UID that is available within the UID bracket

  Exceptions:
    None
  '''
  uids = [ int(users[i][2]) for i in users ]
  uid_found = False
  new_uid = start_uid 
  while not uid_found:
    if new_uid in uids:
      new_uid += 1
    else:
      uid_found = True 
  
  return new_uid

def send_passwd(passwd, user_principal_name, email, host, api_key):
  '''
  Sends a notify email to AAD Sync user. Forwarding a supplied password
  and the host environment where it is located.
  
  Parameters:
    passwd (str): Password to be emailed to AAD Sync user
    user_principal_name (str): AAD sync user's AAD <env>.onmicrosoft.com email
    email (str): AAD sync user's noted email
    host (str): Host environment where AAD sync user is generated
    api_key (str): Sendgrid API Key required to authenticate with Sengrid SaaS in Azure

  Returns: 
    Response of API request against Microsoft Graph Users Send Email

  Exceptions:
    HTTPError as e: '''

  sg = sendgrid.SendGridAPIClient(api_key=api_key)
  data = {
    "personalizations": [
      {
        "to": [
          {
            "email": email
          }
        ],
        "subject": 'One time password for %s on host %s' % (user_principal_name, host)
      }
    ],
    "from": {
      "email": "no-reply@em307.repository.sit.myhealthrecord.gov.au"
    },
    "content": [
      {
        "type": "text/plain",
        "value": '''
User,

You have had an account created on %s

A one time used password has been created on you behalf, this can be
used to access the host and create a new password.

%s

You will be prompted to create a new login when you sign in for the first time.
''' % (host, passwd)
      }
    ]
  }

  try:
    res = sg.client.mail.send.post(request_body=data)
    return res
  except HTTPError as e:
    print(e.to_dict)
    sys.exit(1)


### Main Loop
## Section manages the execution order of the application logic.
config = get_config()
auth_token = get_token(config)

# Gather all of the data that is required to validate an prepare users.
# Get Users -> Validate -> Generate Passwords.
members = get_group_members(config['auth_group'], auth_token)
linux_users = validate_users(config['user_environment'], config['aad_domain'], members)
password_users = create_passwd(password_length, linux_users)

# Manage the user sync on the local host so /etc/passwd can mirror the data 
# in the AAD group.
new_users = user_management(user_uid_low, user_uid_high, password_users)

# Email One-Time-Passwords to newly created users
for user in new_users:
  res = send_passwd(user['linuxPasswd'], user['userPrincipalName'], user['mail'], config['account_use'], config['sendgrid_key'])
  print(res)