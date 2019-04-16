import os

DEMO_CREDENTIALS = {
    'client_id': 'C-9rtYgOP3mjHhw0qu6Tx9fgk9JfZGmbMqn-rnDZnZwI',
    'client_secret': 'Sv9-vNfocFiTe_NoMRkvNLe_jRRFeESHo8A0Uhyp7e28',
    'api_endpoint': 'https://api.figo.me',
}

DEMO_TOKEN = ('ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexTo'
              '22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ')

CREDENTIALS = {
    'client_id': os.getenv('FIGO_CLIENT_ID', DEMO_CREDENTIALS['client_id']),
    'client_secret': os.getenv('FIGO_CLIENT_SECRET', DEMO_CREDENTIALS['client_secret']),
    'api_endpoint': os.getenv('FIGO_API_ENDPOINT', DEMO_CREDENTIALS['api_endpoint']),
}
