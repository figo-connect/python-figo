import os

BANKATHON_CREDENTIALS = {
    'client_id': 'DKaM2Qu9uSICMQxJGRgwD4g',
    'client_secret': 'bankathon2017berlin',
    'api_endpoint': 'https://staging.figo.me',
    # string containing comma-separated list of SSL fingerprints
    'ssl_fingerprints': ('83:2C:BA:FF:87:4F:90:C8:84:EA:F0:3B:2D:E9:AD:5D:8E:D3:48:01'),
}

DEMO_TOKEN = ('ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexTo'
              '22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ')

CREDENTIALS = {
    'client_id': os.getenv('FIGO_CLIENT_ID', BANKATHON_CREDENTIALS['client_id']),
    'client_secret': os.getenv('FIGO_CLIENT_SECRET', BANKATHON_CREDENTIALS['client_secret']),
    'api_endpoint': os.getenv('FIGO_API_ENDPOINT', BANKATHON_CREDENTIALS['api_endpoint']),
    'ssl_fingerprints': os.getenv('FIGO_SSL_FINGERPRINT', BANKATHON_CREDENTIALS['ssl_fingerprints']),
}
