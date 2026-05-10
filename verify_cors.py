import urllib.request, urllib.error, time

API    = 'https://ojekcmosgj.execute-api.us-east-1.amazonaws.com/dev'
ORIGIN = 'http://cloudsentinel-frontend-871070087236.s3-website-us-east-1.amazonaws.com'

print('Waiting 30 seconds for API Gateway propagation...')
time.sleep(30)

routes = ['/scan-cloud-infra', '/risks', '/validate-connection', '/chat', '/disconnect']
print()
print('Testing 401 response CORS headers:')
print('-' * 60)
all_ok = True
for path in routes:
    url    = API + path
    method = 'GET' if path == '/risks' else 'POST'
    req    = urllib.request.Request(url, data=b'{}' if method == 'POST' else None, method=method)
    req.add_header('Content-Type',  'application/json')
    req.add_header('Authorization', 'bad-token-intentional')
    req.add_header('Origin', ORIGIN)
    try:
        urllib.request.urlopen(req, timeout=10)
        print(f'  [??] {path:<28}  got 200 unexpectedly')
    except urllib.error.HTTPError as e:
        acao = e.headers.get('Access-Control-Allow-Origin', 'MISSING')
        ok   = acao != 'MISSING'
        if not ok:
            all_ok = False
        mark = 'OK  ' if ok else 'FAIL'
        print(f'  [{mark}] {path:<28} HTTP {e.code}  ACAO={acao}')
    except Exception as ex:
        all_ok = False
        print(f'  [ERR] {path}: {ex}')

print('-' * 60)
if all_ok:
    print()
    print('ALL PASS - TypeError: Failed to fetch is now FIXED.')
    print('Browser gets a proper 401. The apiFetch auto-refresh will handle it.')
else:
    print()
    print('SOME ROUTES STILL NEED CORS - see above.')
