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
        self.sut.get_account("A1.2")
        
        # account sub-resources
        self.sut.get_account("A1.2").balance
        self.sut.get_account("A1.2").transactions

    def test_global_transactions(self):
        self.sut.transactions

    def test_notifications(self):
        self.sut.notifications
        
    
