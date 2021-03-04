ERROR_MESSAGES = {
    400: {
        "message": "bad request",
        "description": "Bad request",
        "code": 90000,
    },
    401: {
        "message": "unauthorized",
        "description": "Missing, invalid or expired access token.",
        "code": 90000,
    },
    403: {
        "message": "forbidden",
        "description": "Insufficient permission.",
        "code": 90000,
    },
    404: {"message": "not_found", "description": "Not found.", "code": 90000},
    405: {
        "message": "method_not_allowed",
        "description": "Unexpected request method.",
        "code": 90000,
    },
    423: {
        "message": "resource_locked",
        "description": "Resource locked",
        "code": 1008,
    },
    503: {
        "message": "service_unavailable",
        "description": "Exceeded rate limit.",
        "code": 90000,
    },
    504: {
        "message": "upstream_request_timeout",
        "description": "Upstream request timeout.",
        "code": 90000,
    },
}


class FigoException(Exception):
    """Base class for all exceptions transported via the figo connect API.

    They consist of a code-like `error` and a human readable
    `error_description`.
    """

    def __init__(self, error, error_description, code=None):
        """Create a Exception with a error code and error description."""
        self.error = error
        self.error_description = error_description
        self.code = code

    def __str__(self):
        """String representation of the FigoException."""
        code_err = "- code: {}".format(self.code) if self.code else ""
        return (
            f"FigoException: {self.error_description} ({self.error}){code_err}"
        )

    @classmethod
    def from_dict(cls, dictionary):
        """Helper function creating an exception instance from the dictionary
        returned by the server.
        """
        return cls(
            dictionary["error"].get("message"),
            dictionary["error"].get("description"),
            dictionary["error"].get("code"),
        )


class FigoPinException(FigoException):
    """This exception is thrown if the wrong pin was submitted to a task. It
    contains information about current state of the task.
    """

    def __init__(
        self,
        country,
        credentials,
        bank_code,
        iban,
        save_pin,
        error="Wrong PIN",
        error_description=(
            "You've entered a wrong PIN, please provide a new one."
        ),
        code=None,
    ):
        """Initialise an Exception for a wrong PIN which contains information
        about the task.
        """
        super().__init__(error, error_description, code)

        self.country = country
        self.credentials = credentials
        self.bank_code = bank_code
        self.iban = iban
        self.save_pin = save_pin

    def __str__(self):
        """String representation of the FigoPinException."""
        return f"FigoPinException: {self.error_description}({self.error})"
