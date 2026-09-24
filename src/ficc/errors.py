# SPDX-License-Identifier: Apache-2.0
"""Define safe API failures."""


class Failure(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        self.code = code
        self.message = message
        self.status = status
        super().__init__(message)
