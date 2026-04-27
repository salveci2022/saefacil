import urllib.request, json

TOKEN = json.loads(open('tok.txt').read())['token']
EMAILS = ['patsam@hotmail.com.br', 'patsam22042007@gmail.com']

for email in EMAILS:
    req = urllib.request.Request(
        'https://saefacil.onrender.com/api/webhook/ativar-manual',
        json.dumps({'email': email, 'dias': 35}).encode(),
        {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + TOKEN}
    )
    try:
        r = urllib.request.urlopen(req).read()
        print('OK:', email, r)
    except Exception as e:
        print('ERRO:', email, e)