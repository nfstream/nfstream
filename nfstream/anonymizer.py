"""
------------------------------------------------------------------------------------------------------------------------
anonymizer.py
Copyright (C) 2019-22 - NFStream Developers
This file is part of NFStream, a Flexible Network Data Analysis Framework (https://www.nfstream.org/).
NFStream is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
version.
NFStream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
You should have received a copy of the GNU Lesser General Public License along with NFStream.
If not, see <http://www.gnu.org/licenses/>.
------------------------------------------------------------------------------------------------------------------------
"""

from hashlib import blake2b
import secrets


class NFAnonymizer(object):
    """
    NFAnonymizer: NFStream anonymization implementation.
    Anonymizer is initiated at each time to_csv or to_pandas is called with a random secret key (64 bytes).
    Each specified column is anonymized using blake2b algorithm (digest_size: 64 bytes).
    """

    __slots__ = ("_secret", "_cols_names", "_cols_index", "_enabled")

    def __init__(self, cols_names):
        self._secret = secrets.token_bytes(64)
        self._cols_names = cols_names
        self._cols_index = None
        self._enabled = False
        if len(self._cols_names) > 0:
            self._enabled = True

    def process(self, flow):
        if self._enabled:
            if (
                self._cols_index is None
            ):  # First flow, we extract indexes of cols to anonymize.
                self._cols_index = []
                for col_name in self._cols_names:
                    keys = flow.keys()
                    try:
                        self._cols_index.append(keys.index(col_name))
                    except ValueError:
                        print(
                            "WARNING: NFlow do not have {} attribute. Skipping anonymization."
                        )
            values = flow.values()
            for col_idx in self._cols_index:
                value = values[col_idx]
                # Absent values must stay absent. Hashing "" yields a digest that is
                # constant for the whole export and indistinguishable from a real one,
                # so consumers would see a large cohort apparently sharing a value.
                # Only str is compared against "": this is deliberately neither a
                # truthiness test, since 0 and False are legitimate values that must
                # still be anonymized, nor an unguarded equality, since a plugin may
                # store a numpy array whose comparison would not yield a bool.
                is_absent = value is None or (isinstance(value, str) and value == "")
                if not is_absent:
                    values[col_idx] = blake2b(
                        str(value).encode(), digest_size=64, key=self._secret
                    ).hexdigest()
            return values
        return flow.values()
