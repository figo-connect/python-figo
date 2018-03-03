import os

DEMO_CREDENTIALS = {
    'client_id': 'C-9rtYgOP3mjHhw0qu6Tx9fgk9JfZGmbMqn-rnDZnZwI',
    'client_secret': 'Sv9-vNfocFiTe_NoMRkvNLe_jRRFeESHo8A0Uhyp7e28',
    'api_endpoint': 'https://api.figo.me',
    # string containing comma-separated list of SSL fingerprints
    'ssl_fingerprints': ('79:B2:A2:93:00:85:3B:06:92:B1:B5:F2:24:79:48:58:'
                         '3A:A5:22:0F:C5:CD:E9:49:9A:C8:45:1E:DB:E0:DA:50,'
                         '07:0F:14:AE:B9:4A:FB:3D:F8:00:E8:2B:69:A8:51:5C:'
                         'EE:D2:F5:B1:BA:89:7B:EF:64:32:45:8F:61:CF:9E:33'),
}

DEMO_TOKEN = ('ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexTo'
              '22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ')

CREDENTIALS = {
    'client_id': os.getenv('FIGO_CLIENT_ID', DEMO_CREDENTIALS['client_id']),
    'client_secret': os.getenv('FIGO_CLIENT_SECRET', DEMO_CREDENTIALS['client_secret']),
    'api_endpoint': os.getenv('FIGO_API_ENDPOINT', DEMO_CREDENTIALS['api_endpoint']),
    'ssl_fingerprints': os.getenv('FIGO_SSL_FINGERPRINT', DEMO_CREDENTIALS['ssl_fingerprints']),
}
