import boto3, io, zipfile, os, time

lmb  = boto3.client('lambda', region_name='us-east-1')
BASE = r'd:\project_related\CloudSentinel_AI\modules'

def build_zip(src):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for f in os.listdir(src):
            if f.endswith('.py'):
                zf.write(os.path.join(src, f), f)
    return buf.getvalue()

def wait_ready(fn, attempts=20):
    for _ in range(attempts):
        st = lmb.get_function_configuration(FunctionName=fn).get('LastUpdateStatus', '')
        if st == 'Successful':
            return True
        time.sleep(5)
    return False

retries = [
    ('cloudsentinel-cloud-scanner',      os.path.join(BASE, 'cloud-infra'), 'cloud_scanner.lambda_handler',      300, 256),
    ('cloudsentinel-risk-reader',        os.path.join(BASE, 'cloud-infra'), 'risk_reader.lambda_handler',         30, 128),
    ('cloudsentinel-notification-handler',os.path.join(BASE,'cloud-infra'), 'notification_handler.lambda_handler', 30, 128),
    ('cloudsentinel-validate-connection',os.path.join(BASE, 'cloud-infra'), 'validate_connection.lambda_handler',  30, 128),
    ('cloudsentinel-mobile-analyzer',    os.path.join(BASE, 'mobile'),      'mobile_analyzer.lambda_handler',     120, 256),
    ('cloudsentinel-fullstack-analyzer', os.path.join(BASE, 'fullstack'),   'fullstack_analyzer.lambda_handler',  120, 256),
    ('cloudsentinel-devops-analyzer',    os.path.join(BASE, 'devops'),      'devops_analyzer.lambda_handler',     120, 256),
    ('cloudsentinel-data-eng-analyzer',  os.path.join(BASE, 'data-eng'),    'data_eng_analyzer.lambda_handler',   120, 256),
]

for fn, src, handler, timeout, mem in retries:
    wait_ready(fn)
    lmb.update_function_code(FunctionName=fn, ZipFile=build_zip(src))
    time.sleep(8)
    wait_ready(fn)
    lmb.update_function_configuration(FunctionName=fn, Handler=handler, Timeout=timeout, MemorySize=mem)
    print(f'  [OK] {fn}')

print()
print('All Lambdas updated.')
