#
#  Created by Stefan Richter on 2013-01-12.
#  Copyright (c) 2013 figo GmbH. All rights reserved.
#


import unittest

from figo import FigoSession, Payment
from figo.figo import FigoException
from figo.models import ProcessToken, TaskToken, Process, Notification


class TestSession(unittest.TestCase):

    def setUp(self):
        self.sut = FigoSession("ASHWLIkouP2O6_bgA2wWReRhletgWKHYjLqDaqb0LFfamim9RjexTo22ujRIP_cjLiRiSyQXyt2kM1eXU2XLFZQ0Hro15HikJQT_eNeT_9XQ")

    def test_get_account(self):
        account = self.sut.get_account("A1.2")
        self.assertEqual(account.account_id, "A1.2")

    def test_get_account_tan_schemes(self):
        account = self.sut.get_account("A1.1")
        self.assertEqual(len(account.supported_tan_schemes), 3)

    def test_get_account_balance(self):
        # account sub-resources
        balance = self.sut.get_account_balance(self.sut.get_account("A1.2"))
        self.assertTrue(balance.balance)
        self.assertTrue(balance.balance_date)

    def test_get_account_transactions(self):
        transactions = self.sut.get_account("A1.2").transactions
        self.assertTrue(len(transactions) > 0)

    def test_get_account_payments(self):
        payments = self.sut.get_account("A1.2").payments
        self.assertTrue(len(payments) >= 0)

    def test_get_global_transactions(self):
        transactions = self.sut.transactions
        self.assertTrue(len(transactions) > 0)

    def test_get_global_payments(self):
        payments = self.sut.payments
        self.assertTrue(len(payments) >= 0)

    def test_get_notifications(self):
        notifications = self.sut.notifications
        self.assertTrue(len(notifications) >= 0)

    def test_get_missing_account(self):
        self.assertEqual(self.sut.get_account("A1.22"), None)

    def test_error_handling(self):
        try:
            self.sut.get_sync_url("", "http://localhost:3003/")
            self.fail("no exception encountered")
        except:
            pass

    def test_sync_uri(self):
        self.sut.get_sync_url("qwe", "qew")

    def test_get_mail_from_user(self):
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
        self.assertEqual(self.sut.get_payment(account_or_account_id=modified_payment.account_id, payment_id=modified_payment.payment_id), None)

    def test_set_bank_account_order(self):
        # Access token with accounts=rw needed
        accounts = [self.sut.get_account("A1.2"), self.sut.get_account("A1.1")]
        self.assertRaises(FigoException, self.sut.set_account_sort_order, accounts)

    def test_get_supported_payment_services(self):
        # Access token with accounts=rw needed
        self.assertRaises(FigoException, self.sut.get_supported_payment_services, "de")

    def test_get_login_settings(self):
        # Access token with accounts=rw needed
        self.assertRaises(FigoException, self.sut.get_login_settings, "de", "90090042")

    def test_setup_new_bank_account(self):
        # Access token with accounts=rw needed
        self.assertRaises(FigoException, self.sut.add_account, "de", ["figo", "figo"], "90090042")

    def test_modify_a_transaction(self):
        # Access token with transactions=rw needed
        self.assertRaises(FigoException, self.sut.modify_transaction, "A1.1", "T1.24", False)

    def test_modify_all_transactions_of_account(self):
        # Access token with transactions=rw needed
        self.assertRaises(FigoException, self.sut.modify_account_transactions, "A1.1", False)

    def test_modify_all_transactions(self):
        # Access token with transactions=rw needed
        self.assertRaises(FigoException, self.sut.modify_account_transactions, False)

    def test_delete_transaction(self):
        # Access token with transactions=rw needed
        self.assertRaises(FigoException, self.sut.delete_transaction, "A1.1", "T1.24")

    def test_get_payment_proposals(self):
        proposals = self.sut.get_payment_proposals()
        self.assertEqual(len(proposals), 2)

    def test_start_task(self):
        # Valid task token needed
        task_token = TaskToken(self.sut)
        task_token.task_token = "invalidTaskToken"
        self.assertRaises(FigoException, self.sut.start_task, task_token)

    def test_poll_task_state(self):
        # Valid task token needed
        task_token = TaskToken(self.sut)
        task_token.task_token = "invalidTaskToken"
        self.assertRaises(FigoException, self.sut.get_task_state, task_token)

    def test_cancel_task(self):
        # Valid task token needed
        task_token = TaskToken(self.sut)
        task_token.task_token = "invalidTaskToken"
        self.assertRaises(FigoException, self.sut.cancel_task, task_token)

    def test_start_process(self):
        # Valid process token needed
        process_token = ProcessToken(self.sut)
        process_token.process_token = "invalidProcessToken"
        self.assertRaises(FigoException, self.sut.start_process, process_token)

    def test_create_process(self):
        # Access token with process=rw needed
        process = Process(self.sut, email="demo@demo.de", password="figo", state="qwer", steps=["not_valid"])
        self.assertRaises(FigoException, self.sut.create_process, process)
