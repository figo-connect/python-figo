#
#  Created by Jan van Esdonk on 2015-03-12.
#  Copyright (c) 2015 figo GmbH. All rights reserved.
#
import unittest
from nose.plugins.skip import SkipTest
from figo.figo import FigoConnection, FigoSession, FigoPinException
from figo.models import TaskToken, TaskState, Service, LoginSettings
import time
from uuid import uuid4


class WriteTest(unittest.TestCase):
        
    @classmethod
    def setUpClass(cls):
        cls.CLIENT_ID = "C-9rtYgOP3mjHhw0qu6Tx9fgk9JfZGmbMqn-rnDZnZwI"
        cls.CLIENT_SECRET = "Sv9-vNfocFiTe_NoMRkvNLe_jRRFeESHo8A0Uhyp7e28"
        cls.USER = "testuser@test.de"
        cls.PASSWORD = "some_words"
        
        # bank account info needed
        cls.CREDENTIALS = []
        cls.BANK_CODE = ""        
        
        cls.fc = FigoConnection(cls.CLIENT_ID, cls.CLIENT_SECRET, "https://127.0.0.1/")
        
    @classmethod
    def tearDownClass(cls):
        response = cls.fc.credential_login(cls.USER, cls.PASSWORD)
        fs = FigoSession(response["access_token"])
        fs.remove_user()
            
    def t_01_add_user(self):
        username = "{0}.test@example.com".format(uuid4())
        response = self.fc.add_user("Test", username, self.PASSWORD)
        self.assertTrue(isinstance(response, (str, unicode)))
        response = self.fc.credential_login(username, self.PASSWORD)
        session = FigoSession(response["access_token"])
        session.remove_user()

    def test_010_add_user_and_login(self):

        response = self.fc.add_user_and_login("Test", self.USER, self.PASSWORD)
        self.assertTrue("access_token" in response)

    def test_02_credential_login(self):        
        response = self.fc.credential_login(self.USER, self.PASSWORD)
        self.assertTrue("access_token" in response)
        
    def test_03_get_supported_payment_services(self):
        response = self.fc.credential_login(self.USER, self.PASSWORD)
        fs = FigoSession(response["access_token"])
        services = fs.get_supported_payment_services("de")
        self.assertEqual(26, len(services))
        self.assertTrue(isinstance(services[0], Service))

    @SkipTest
    def test_04_get_login_settings(self):
        response = self.fc.credential_login(self.USER, self.PASSWORD)
        fs = FigoSession(response["access_token"])
        login_settings = fs.get_login_settings("de", self.BANK_CODE)
        self.assertTrue(isinstance(login_settings, LoginSettings))

    @SkipTest
    def t_05_add_account(self):
        response = self.fc.credential_login(self.USER, self.PASSWORD)
        fs = FigoSession(response["access_token"])
        token = fs.add_account("de", self.CREDENTIALS, self.BANK_CODE)
        self.assertTrue(isinstance(token, TaskToken))
        task_state = fs.get_task_state(token)
        time.sleep(5)
        self.assertTrue(isinstance(task_state, TaskState))
        self.assertEqual(1, len(fs.accounts))

    @SkipTest
    def test_050_add_acount_and_sync_wrong_pin(self):
        response = self.fc.credential_login(self.USER, self.PASSWORD)
        fs = FigoSession(response["access_token"])
        wrong_credentials = [self.CREDENTIALS[0], "123456"]
        self.assertRaises(FigoPinException, fs.add_account_and_sync, "de", wrong_credentials, self.BANK_CODE)
        self.assertEqual(0, len(fs.accounts))

    @SkipTest
    def test_051_add_acount_and_sync_wrong_and_correct_pin(self):
        response = self.fc.credential_login(self.USER, self.PASSWORD)
        fs = FigoSession(response["access_token"])
        wrong_credentials = [self.CREDENTIALS[0], "123456"]
        try:
            task_state = fs.add_account_and_sync("de", wrong_credentials, self.BANK_CODE)
        except FigoPinException as pin_exception:
            task_state = fs.add_account_and_sync_with_new_pin(pin_exception, self.CREDENTIALS[1])
        time.sleep(5)
        self.assertTrue(isinstance(task_state, TaskState))
        self.assertEqual(1, len(fs.accounts))

    @SkipTest
    def test_06_modify_transaction(self):
        response = self.fc.credential_login(self.USER, self.PASSWORD)
        fs = FigoSession(response["access_token"])
        account = fs.accounts[0]
        transaction = account.transactions[0]
        response = fs.modify_transaction(account.account_id, transaction.transaction_id, False)
        self.assertEqual(False, response.visited)
        response = fs.modify_transaction(account.account_id, transaction.transaction_id, True)
        self.assertEqual(True, response.visited)

    @SkipTest
    def test_07_modify_account_transactions(self):
        response = self.fc.credential_login(self.USER, self.PASSWORD)
        fs = FigoSession(response["access_token"])
        account = fs.accounts[0]
        fs.modify_account_transactions(account.account_id, False)
        [self.assertFalse(transaction.visited) for transaction in account.transactions]
        fs.modify_account_transactions(account.account_id, True)
        [self.assertTrue(transaction.visited) for transaction in account.transactions]
        
    def test_08_modify_user_transactions(self):
        response = self.fc.credential_login(self.USER, self.PASSWORD)
        fs = FigoSession(response["access_token"])
        response = fs.modify_user_transactions(False)
        [self.assertFalse(transaction.visited) for transaction in fs.transactions]
        response = fs.modify_user_transactions(True)
        [self.assertTrue(transaction.visited) for transaction in fs.transactions]

    @SkipTest
    def test_09_delete_transaction(self):
        response = self.fc.credential_login(self.USER, self.PASSWORD)
        fs = FigoSession(response["access_token"])
        account = fs.accounts[0]
        transaction = account.transactions[0]
        transaction_count = len(account.transactions)
        fs.delete_transaction(account.account_id, transaction.transaction_id)
        self.assertEqual(transaction_count-1, len(account.transactions))
