#!/usr/bin/env python

from figo.credentials import DEMO_TOKEN
from figo import FigoSession


def main():
    session = FigoSession(DEMO_TOKEN)

    for account in session.accounts:
        print(account)
        print(u'  {}'.format(account.balance))
        print(u'  Transactions:')

        for transaction in session.get_account(account.account_id).transactions:
            print(u'    {}'.format(transaction))


if __name__ == "__main__":
    main()
