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
    500: {
        "message": "internal_server_error",
        "description": "We are very sorry, but something went wrong",
        "code": 90000,
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

    def __init__(
        self, error, error_description, code=None, data=None, status_code=None
    ):
        """Create a Exception with a error code and error description."""
        self.error = error
        self.error_description = error_description
        self.code = code
        self.data = data
        self.status_code = status_code

    def __str__(self):
        """String representation of the FigoException."""
        code_err = "- code: {}".format(self.code) if self.code else ""
        return (
            f"FigoException: {self.error_description} ({self.error}){code_err}"
        )

    @classmethod
    def from_dict(cls, dictionary, status_code=None):
        """Helper function creating an exception instance from the dictionary
        returned by the server.
        """
        return cls(
            dictionary["error"].get("message"),
            dictionary["error"].get("description"),
            code=dictionary["error"].get("code"),
            data=dictionary["error"].get("data"),
            status_code=status_code,
        )
