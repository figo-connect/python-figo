from flask import Flask, render_template, session, redirect, request
from flask_bootstrap import Bootstrap
from jinja2.utils import soft_unicode

# patch sys.path
import sys
if sys.path[0] != '':
    sys.path.insert(0, '')

from figo import FigoSession, FigoConnection

app = Flask(__name__)
app.secret_key = 'W0\xb9>\x85\xe8\x8f\x00\x18\x9f\x87\xca\x9a\x9f\xe0np\xa1o\xbf\x9d6Ou'
Bootstrap(app)

CLIENT_ID = "CaESKmC8MAhNpDe5rvmWnSkRE_7pkkVIIgMwclgzGcQY"
CLIENT_SECRET = "STdzfv0GXtEj_bwYn7AgCVszN1kKq5BdgEIKOM_fzybQ"
connection = FigoConnection(CLIENT_ID, CLIENT_SECRET, "http://localhost:3000/callback")

@app.template_filter('ff')
def figo_format(value, *args, **kwargs):
    """
    Apply python string formatting on an object:

    .. sourcecode:: jinja

        {{ "%s - %s"|format("Hello?", "Foo!") }}
            -> Hello? - Foo!
    """
    if args and kwargs:
        raise FilterArgumentError('can\'t handle positional and keyword arguments at the same time')
    if args:
        return soft_unicode(value.format(*args))
    else:
        return soft_unicode(value.format(**kwargs))

@app.route("/")
@app.route("/<current_account_id>")
def root(current_account_id=None):
    # check whether the user is logged in
    if not 'figo_token' in session:
        return redirect(connection.login_url(scope="accounts=ro transactions=ro balance=ro user=ro", state="qweqwe"))

    # open user figo connection
    figo_session = FigoSession(session['figo_token'])

    # open demo figo connection
    #figo_session = FigoSession("ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexTo22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ")

    if current_account_id:
        current_account = figo_session.get_account(current_account_id)
    else:
        current_account = None

    if current_account:
        transactions = current_account.transactions
    else:
        transactions = figo_session.transactions

    return render_template('banking_root.html', accounts=figo_session.accounts, current_account=current_account, transactions=transactions, user=figo_session.user)

# Example: http://localhost:5000/callback?state=qweqwe&code=OagY3AZwv0WB0GDVRFQrPUO_yFIM50avG1UEu5iXSZwDxvVdOTbg9UWfR12sawiIFghV0K0rWQEr6n1NNFM7JqJh-yWhk5Q-vnDYZqaXnk4Y
@app.route("/callback")
def process_redirect():
    # authenticate the call
    if request.args.get('state') != "qweqwe":
        raise Exception("Bogus redirect, wrong state")

    # trade in authentication code for access token
    token_dict = connection.convert_authentication_code(request.args.get("code"))

    # store the access token in our session
    session['figo_token'] = token_dict['access_token']

    return redirect("/")

@app.route("/logout")
def logout():
    if 'figo_token' in session:
        del session['figo_token']

    return redirect("/")

if __name__ == "__main__":
    app.run(port=3000, debug=True)
