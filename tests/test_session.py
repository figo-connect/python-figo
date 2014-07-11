#
#  Created by Stefan Richter on 2013-01-12.
#  Copyright (c) 2013 figo GmbH. All rights reserved.
#


import unittest

from figo import FigoSession, Payment, Notification


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

        #bank = self.sut.get_account("A1.2").bank

        transactions = self.sut.get_account("A1.2").transactions
        self.assertTrue(len(transactions) > 0)

        payments = self.sut.get_account("A1.2").payments
        self.assertTrue(len(payments) >= 0)

    def test_global_transactions(self):
        transactions = self.sut.transactions
        self.assertTrue(len(transactions) > 0)

    def test_global_payments(self):
        payments = self.sut.payments
        self.assertTrue(len(payments) >= 0)

    def test_notifications(self):
        notifications = self.sut.notifications
        self.assertTrue(len(notifications) >= 0)

    def test_missing_handling(self):
        self.assertEqual(self.sut.get_account("A1.22"), None)

    def test_error_handling(self):
        try:
            self.sut.get_sync_url("", "http://localhost:3003/")
            self.fail("no exception encountered")
        except:
            pass

    def test_sync_uri(self):
        self.sut.get_sync_url("qwe", "qew")

    def test_user(self):
        self.assertEqual(self.sut.user.email, "demo@figo.me")

    def test_create_update_delete_notification(self):
        added_notification = self.sut.add_notification(Notification.from_dict(self.sut, dict(observe_key="/rest/transactions", notify_uri="http://figo.me/test", state="qwe")))
        self.assertEqual(added_notification.observe_key, "/rest/transactions")
        self.assertEqual(added_notification.notify_uri, "http://figo.me/test")
        self.assertEqual(added_notification.state, "qwe")

        added_notification.state = "asd"
        modified_notification = self.sut.modify_notification(added_notification)
        self.assertEqual(modified_notification.observe_key, "/rest/transactions")
        self.assertEqual(modified_notification.notify_uri, "http://figo.me/test")
        self.assertEqual(modified_notification.state, "asd")

        self.sut.remove_notification(modified_notification.notification_id)
        self.assertEqual(self.sut.get_notification(modified_notification.notification_id), None)

    def test_create_update_delete_payment(self):
        added_payment = self.sut.add_payment(Payment.from_dict(self.sut, dict(account_id="A1.1", type="Transfer", account_number="4711951501", bank_code="90090042", name="figo", purpose="Thanks for all the fish.", amount=0.89)))
        self.assertEqual(added_payment.account_id, "A1.1")
        self.assertEqual(added_payment.bank_name, "Demobank")
        self.assertEqual(added_payment.amount, 0.89)

        added_payment.amount = 2.39
        modified_payment = self.sut.modify_payment(added_payment)
        self.assertEqual(modified_payment.payment_id, added_payment.payment_id)
        self.assertEqual(modified_payment.account_id, "A1.1")
        self.assertEqual(modified_payment.bank_name, "Demobank")
        self.assertEqual(modified_payment.amount, 2.39)

        self.sut.remove_payment(modified_payment)
        self.assertEqual(self.sut.get_payment(account_id=modified_payment.account_id, payment_id=modified_payment.payment_id), None)
