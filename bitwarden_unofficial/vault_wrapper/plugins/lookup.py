# lookup.py
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import subprocess
import tempfile
from threading import Lock

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError

class BitwardenCliWrapper:

    def __init__(self):

        # It will be cleaned on object destruction
        self._tempdir_obj = tempfile.TemporaryDirectory()
        self._tmp_dir = self._tempdir_obj.name

    def cleanup(self):
        # Explicitly clean up temporary directory
        self._tempdir_obj.cleanup()

    def get_secret(self, bw_url:str, bw_client_id:str, bw_client_secret:str, bw_password:str, secret_id:str, secret_type:str):
        env = os.environ.copy()
        env['HOME'] = self._tmp_dir
        env['BW_CLIENTID'] = bw_client_id
        env['BW_CLIENTSECRET'] = bw_client_secret

        def run(command, **kwargs):
            try:
                result = subprocess.run(
                    command,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                    text=True,
                    **kwargs
                )
                return result.stdout.strip()
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Command failed: {' '.join(command)}\n{e.stderr.strip()}")

        # Step 1: Set Bitwarden server - TODO add logging here
        run(['bw', 'config', 'server', bw_url])

        # Step 2: Log in using the API key (client ID/secret)
        run(['bw', 'login', '--apikey'])

        # Step 3: Sync
        run(['bw', 'sync'])

        # Step 4: Unlock vault
        run(['bw', 'unlock', bw_password])

        # Step 5: Read secret value and return it
        # bw get (item|username|password|uri|totp|exposed|attachment|folder|collection|organization|org-collection|template|fingerprint) <id> [options]
        run(['bw', 'get', secret_type, secret_id])
        



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


class LookupModule(LookupBase):
    ALLOWED_LOOKUP_TYPES=["item","username","password","uri","totp","exposed","attachment","folder","collection","organization","org-collection","template","fingerprint"]
    
    def run(self, terms, variables=None, **kwargs):
        if len(terms) != 2:
            raise AnsibleError("You must provide the type and the id to lookup")
        secret_type = terms[0]
        if secret_type not in LookupModule.ALLOWED_LOOKUP_TYPES:
            raise AnsibleError("You must provide a valid type between item|username|password|uri|totp|exposed|attachment|folder|collection|organization|org-collection|template|fingerprint")
        secret_id = terms[1]
        
        # Load configuration from kwargs or fallback to environment variables
        config = BWConfig(**kwargs)

        bw_cli = BitwardenCliWrapper()

        return bw_cli.get_secret(config.url,config.client_id,config.client_secret,config.vault_password,secret_id,secret_type)


