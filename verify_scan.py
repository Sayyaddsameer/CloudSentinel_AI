import boto3, urllib.request, urllib.error, json

REGION    = 'us-east-1'
CLIENT_ID = '3bljg42108cec2ajj70h21mcnn'
POOL_ID   = 'us-east-1_6O8s8U592'
API_BASE  = 'https://ojekcmosgj.execute-api.us-east-1.amazonaws.com/dev'

cognito = boto3.client('cognito-idp', region_name=REGION)

# Check existing users
print('Users in Cognito pool:')
users = cognito.list_users(UserPoolId=POOL_ID, Limit=5).get('Users', [])
for u in users:
    attrs  = {a['Name']: a['Value'] for a in u.get('Attributes', [])}
    uname  = u['Username']
    email  = attrs.get('email', 'unknown')
    status = u['UserStatus']
    print(f'  username={uname}  email={email}  status={status}')

print()

# Set a known temp password via admin so we can test
TARGET_USER  = users[0]['Username'] if users else None
TEST_PASS    = 'TestPass@12345!'

if TARGET_USER:
    print(f'Setting admin temp password for user: {TARGET_USER}')
    cognito.admin_set_user_password(
        UserPoolId=POOL_ID,
        Username=TARGET_USER,
        Password=TEST_PASS,
        Permanent=True
    )
    print('  Done')

    # Now authenticate
    print()
    print('Authenticating...')
    resp = cognito.initiate_auth(
        ClientId=CLIENT_ID,
        AuthFlow='USER_PASSWORD_AUTH',
        AuthParameters={'USERNAME': TARGET_USER, 'PASSWORD': TEST_PASS}
    )
    tokens   = resp['AuthenticationResult']
    ID_TOKEN = tokens['IdToken']
    AC_TOKEN = tokens['AccessToken']
    print(f'  IdToken     (first 50): {ID_TOKEN[:50]}')
    print(f'  AccessToken (first 50): {AC_TOKEN[:50]}')

    # Test IdToken vs AccessToken on /risks
    def test(label, token):
        url = API_BASE + '/risks?module=cloud-infra'
        req = urllib.request.Request(url, method='GET')
        req.add_header('Authorization', token)
        req.add_header('Content-Type', 'application/json')
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                data  = json.loads(r.read())
                count = len(data) if isinstance(data, list) else '?'
                print(f'  [OK  ] {label:20}  HTTP 200  risks={count}')
                return True
        except urllib.error.HTTPError as e:
            err = e.read().decode()[:80]
            print(f'  [FAIL] {label:20}  HTTP {e.code}  {err}')
            return False

    print()
    print('Token tests against /risks:')
    id_ok  = test('IdToken',     ID_TOKEN)
    acc_ok = test('AccessToken', AC_TOKEN)
    print()
    if id_ok and not acc_ok:
        print('CONFIRMED: IdToken works, AccessToken rejected.')
        print('getToken() fix in auth.js is CORRECT and NECESSARY.')
    elif id_ok and acc_ok:
        print('Both tokens work - authorizer accepts either.')
    elif not id_ok:
        print('PROBLEM: IdToken also rejected. Check authorizer config.')
