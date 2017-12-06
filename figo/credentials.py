import os

DEMO_CREDENTIALS = {
    'client_id': 'C-9rtYgOP3mjHhw0qu6Tx9fgk9JfZGmbMqn-rnDZnZwI',
    'client_secret': 'Sv9-vNfocFiTe_NoMRkvNLe_jRRFeESHo8A0Uhyp7e28',
    'api_endpoint': 'https://api.figo.me/v3',
    # string containing comma-separated list of SSL fingerprints
    'ssl_fingerprints': ('79:B2:A2:93:00:85:3B:06:92:B1:B5:F2:24:79:48:58:'
                         '3A:A5:22:0F:C5:CD:E9:49:9A:C8:45:1E:DB:E0:DA:50,'
                         'B7:52:32:2B:4B:DC:C9:74:B1:65:A7:9E:8D:F9:44:E5:'
                         'A1:62:2D:D3:43:27:A7:AA:F5:F7:B7:FA:D9:C3:1B:0A'),
}

DEMO_TOKEN = ('ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexTo'
              '22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ')

CREDENTIALS = {
    'client_id': os.getenv('FIGO_CLIENT_ID', DEMO_CREDENTIALS['client_id']),
    'client_secret': os.getenv('FIGO_CLIENT_SECRET', DEMO_CREDENTIALS['client_secret']),
    'api_endpoint': os.getenv('FIGO_API_ENDPOINT', DEMO_CREDENTIALS['api_endpoint']),
    'ssl_fingerprints': os.getenv('FIGO_SSL_FINGERPRINT', DEMO_CREDENTIALS['ssl_fingerprints']),
}
