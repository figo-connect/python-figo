#!/usr/bin/env python

from figo.credentials import DEMO_TOKEN
from figo import FigoSession


def main():
    session = FigoSession(DEMO_TOKEN)

    # print out a list of accounts including its balance
    for account in session.accounts:
        print(account)
        print(account.balance)

    # print out the list of all transactions on a specific account
    for transaction in session.get_account("A1.2").transactions:
        print(transaction)

if __name__ == "__main__":
    main()
