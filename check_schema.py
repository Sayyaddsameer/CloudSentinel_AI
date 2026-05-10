import boto3, json

ddb   = boto3.client('dynamodb',   region_name='us-east-1')
table = ddb.describe_table(TableName='cloudsentinel-risks')['Table']

print('=== DynamoDB Table: cloudsentinel-risks ===')
print('Key Schema:')
for k in table['KeySchema']:
    print(f'  {k["AttributeName"]}  ({k["KeyType"]})')

print()
print('Attributes:')
for a in table['AttributeDefinitions']:
    print(f'  {a["AttributeName"]}  ({a["AttributeType"]})')

print()
print('GSIs:')
for gsi in table.get('GlobalSecondaryIndexes', []):
    name = gsi['IndexName']
    keys = gsi['KeySchema']
    print(f'  {name}')
    for k in keys:
        print(f'    {k["AttributeName"]}  ({k["KeyType"]})')

# Also sample one real item to see its structure
print()
print('=== Sample item from DynamoDB ===')
items = ddb.scan(TableName='cloudsentinel-risks', Limit=1).get('Items', [])
if items:
    for k, v in items[0].items():
        val = list(v.values())[0]
        print(f'  {k}: {str(val)[:80]}')
else:
    print('  No items found')
