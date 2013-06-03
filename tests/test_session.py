#
#  Created by Stefan Richter on 2013-01-12.
#  Copyright (c) 2013 figo GmbH. All rights reserved.
#


import unittest

from figo import FigoSession

class TestSession(unittest.TestCase):
    
    def setUp(self):
        self.sut = FigoSession("ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexTo22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ")

    def test_accounts(self):
        self.sut.accounts
        self.sut.get_account("A1.1")
        account = self.sut.get_account("A1.2")
        self.assertEqual(account.account_id, "A1.2")
        
        # account sub-resources
        balance = self.sut.get_account("A1.2").balance
        self.assertTrue(balance.balance)
        self.assertTrue(balance.balance_date)
        
        transactions = self.sut.get_account("A1.2").transactions
        self.assertGreater(len(transactions), 0)

    def test_global_transactions(self):
        transactions = self.sut.transactions
        self.assertGreater(len(transactions), 0)

    def test_notifications(self):
        notifications = self.sut.notifications
        self.assertGreater(len(notifications), 0)

    def test_sync_uri(self):
        self.sut.get_sync_url("qwe", "qew")

    def test_create_update_delete_notification(self):
        notification_id = self.sut.add_notification(observe_key="/rest/transactions", notify_uri="http://figo.me/test", state="qwe")
        notification = self.sut.get_notification(notification_id)
        self.assertEqual(notification.observe_key, "/rest/transactions")
        self.assertEqual(notification.notify_uri, "http://figo.me/test")
        self.assertEqual(notification.state, "qwe")

        self.sut.modify_notification(notification_id, state="asd")
        notification = self.sut.get_notification(notification_id)
        self.assertEqual(notification.observe_key, "/rest/transactions")
        self.assertEqual(notification.notify_uri, "http://figo.me/test")
        self.assertEqual(notification.state, "asd")

        self.sut.remove_notification(notification_id)
        self.assertEqual(self.sut.get_notification(notification_id), None)
