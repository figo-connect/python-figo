from .models import Account


def get_account_id(account_or_account_id):
    if account_or_account_id is None:
        return None
    elif isinstance(account_or_account_id, Account):
        return account_or_account_id.account_id
    else:
        return account_or_account_id


def filter_keys(options, allowed_keys):
    if options is None or options == {}:
        return {}
    else:
        keys = [key for key in options.keys() if key in allowed_keys]
        return dict(zip(keys, [options[key] for key in keys]))


def filter_none(dict_obj):
    return {k: v for k, v in dict_obj.items() if v is not None}
