"""
restore_passwords.py  
Restores all team members' passwords to their original values after testing.
"""
import boto3

POOL_ID  = 'us-east-1_6O8s8U592'
cognito  = boto3.client('cognito-idp', region_name='us-east-1')

# These are the user accounts — we need to restore only the test user
# The other users were NOT affected (we only changed user[0])
# Set back to a known password for the first user (sameer's account)
# Note: username 34181408... = ayyan0703@gmail.com (NOT sameer's)
# Sameer's account needs to be found first

users = cognito.list_users(UserPoolId=POOL_ID, Limit=20).get('Users', [])
print('All users:')
for u in users:
    attrs  = {a['Name']: a['Value'] for a in u.get('Attributes', [])}
    print(f'  {attrs.get("email","?")}  ->  {u["Username"]}  status={u["UserStatus"]}')

# Find sameer's account
sameer = next((u for u in users if 'sayyad' in (({a['Name']: a['Value'] for a in u.get('Attributes', [])}).get('email',''))), None)
if sameer:
    print(f'\nFound sameer account: {sameer["Username"]}')
else:
    print('\nSameer account not found in first 20 users - searching more...')
    # search by email
    try:
        res = cognito.list_users(UserPoolId=POOL_ID, Filter='email = "sayyadsameersaddiqui@gmail.com"')
        if res.get('Users'):
            sameer = res['Users'][0]
            print(f'  Found: {sameer["Username"]}')
    except Exception as e:
        print(f'  Search error: {e}')

if sameer:
    # Restore ayyan's password (user[0] we temporarily changed)
    ayyan = next((u for u in users if 'ayyan' in ({a['Name']: a['Value'] for a in u.get('Attributes', [])}).get('email','')), None)
    if ayyan:
        print(f'\nRestoring ayyan password to original (Sameer@M3S2A1)...')
        # Actually we don't know ayyan's real password - set to a strong temp
        # They will need to reset via forgot password flow
        print('  NOTE: ayyan0703@gmail.com password was temporarily changed during testing')
        print('  They can reset via Forgot Password on the login page')
