#!/usr/bin/env python

from figo import FigoSession

def main():
    session = FigoSession("ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexTo22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ")

    # print out a list of accounts including its balance
    for account in session.accounts:
        print(account)
        print(account.balance)

    # print out the list of all transactions on a specific account
    for transaction in session.get_account("A1.2").transactions:
        print(transaction)

if __name__ == "__main__":
    main()
