#
#  Created by Matthias Jacob on 2013-08-19.
#  Copyright (c) 2013 figo GmbH. All rights reserved.
#


class FigoException(Exception):
    """Base class for all exceptions transported via the figo connect API.

    They consist of a code-like `error` and a human readable `error_description`.
    """

    def __init__(self, error, error_description):
        self.error = error
        self.error_description = error_description

    def __str__(self):
        return repr(self.error_description)

    @classmethod
    def from_dict(cls, dictionary):
        return cls(dictionary['error'], dictionary['error_description'])
