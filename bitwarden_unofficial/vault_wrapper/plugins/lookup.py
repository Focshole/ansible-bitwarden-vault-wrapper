# lookup.py
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError

import shutil
import tempfile
from threading import Lock

class BitwardenCliWrapper:
    _instance = None
    _lock = Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(BitwardenCliWrapper, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized') and self._initialized:
            return
        self._initialized = True

        # Set up the temporary directory with automatic cleanup
        self._tempdir_obj = tempfile.TemporaryDirectory()
        self._tmp_dir = self._tempdir_obj.name

    @property
    def home_dir(self):
        return self._tmp_dir

    def cleanup(self):
        """Explicitly clean up temporary directory."""
        if os.environ.get('HOME') == self._tmp_dir:
            os.environ['HOME'] = self._original_home
        self._tempdir_obj.cleanup()


class BWConfig:
    MANDATORY_PARAMETERS=[
        'BW_CLIENT_ID',
        'BW_CLIENTSECRET',
        'BW_GRANT_TYPE'
    ]
    def __init__(self, **kwargs):
        self.client_id = kwargs.get('BW_CLIENT_ID', os.getenv('BW_CLIENT_ID'))
        self.scope = kwargs.get('BW_SCOPE', os.getenv('BW_SCOPE'))
        self.grant_type = kwargs.get('BW_GRANT_TYPE', os.getenv('BW_GRANT_TYPE'))
        self.url = kwargs.get('BW_URL', os.getenv('BW_URL'))
        self.client_secret = kwargs.get('BW_CLIENTSECRET', os.getenv('BW_CLIENTSECRET')),
        self.vault_password = kwargs.get('BW_VAULT_PASSWORD')

        missing = [k for k, v in self.__dict__.items() if v is None and v not in BWConfig.MANDATORY_PARAMETERS]
        if missing:
            raise ValueError(f"Missing required configuration values: {', '.join(missing)}")

class BitwardenCliWrapper():
    def __init__(self):
        pass

class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        if len(terms) != 1:
            raise AnsibleError("You must provide the key to lookup")

        key = terms[0]
        # Load configuration from kwargs or fallback to environment variables
        config = BWConfig(**kwargs)

