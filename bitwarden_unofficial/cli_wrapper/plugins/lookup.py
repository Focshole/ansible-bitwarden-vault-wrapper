#!/usr/bin/env python3
import os
import re
import subprocess
import tempfile

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
from ansible.utils.display import Display
from hashlib import sha256
display = Display()

class ExecutableException(Exception):
    def __init__(self, *args):
        super().__init__(*args)

class ExecutableWrapper:
    def __init__(self, env:dict[str,str]):
        self._env = env
    
    def run(self, command:str, **kwargs):
        try:
            result = subprocess.run(
                command,
                env=self._env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True,
                **kwargs,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise ExecutableException(f"Command failed: '{'\' \''.join(command)}\n{e.stderr.strip()}'",e)


class BitwardenCliWrapper:
    VARIABLE_KEY="BitwardenCliWrapper"

    def __init__(self,variables):
        self._bw_tmp_homes_dict, self._bw_session_cli_dict=self._get_or_create_bw_session_cli_dicts(variables)

    def _get_or_create_bw_session_cli_dicts(self,variables) -> tuple[dict,dict]:
        if BitwardenCliWrapper.VARIABLE_KEY not in variables:
            # https://josephharding.github.io/tutorials/2024/05/01/ansible-lookup-plugins-lazy-cache.html
            # First dict is for tmp home dir, second dict is for session keys
            variables[BitwardenCliWrapper.VARIABLE_KEY]=(dict(),dict())
        return variables[BitwardenCliWrapper.VARIABLE_KEY]
        
    def get_secret(
        self,
        bw_url: str,
        bw_client_id: str,
        bw_client_secret: str,
        bw_password: str,
        secret_id: str,
        secret_type: str):
        
        lookup_key=sha256(bytes(f"{bw_url}-{bw_client_id}-{bw_client_secret}-{bw_password}","utf8")).hexdigest()

        bw_env=os.environ.copy()
        bw_env["HOME"] = self._get_tmp_home_dir(lookup_key)
        bw_env["BW_CLIENTID"] = bw_client_id
        bw_env["BW_CLIENTSECRET"] = bw_client_secret
        executable_wrapper = ExecutableWrapper(bw_env)

        if lookup_key not in self._bw_session_cli_dict:
            display.verbose("Set url to '" + bw_url + "'")
            # Step 1: Set Bitwarden server - TODO add logging here
            executable_wrapper.run(["bw", "config", "server", bw_url])

            display.verbose("Logging in using api key")
            # Step 2: Log in using the API key (client ID/secret)
            display.display(executable_wrapper.run(["bw", "login", "--apikey"]))

            # Step 3: Sync
            display.verbose("Syncing the vault...")
            display.display(executable_wrapper.run(["bw", "sync"]))

            # Step 4: Unlock vault
            bw_env["BW_PASSWORD"] = bw_password
            unlock_output = executable_wrapper.run(["bw", "unlock", "--passwordenv", "BW_PASSWORD"])
            bw_env["BW_PASSWORD"] = ""

            # Step 5: Lookup session key from output
            regex_session_key = r'export BW_SESSION="([^"]+)"'
            match = re.search(regex_session_key, unlock_output)
            if match:
                bw_session = match.group(1)
            else:
                raise AnsibleError(
                    "Unlocking failed, probably a wrong vault password had been provided",
                    obj=unlock_output,
                    show_content=True,
                )
            self._bw_session_cli_dict[lookup_key] = bw_session
        else:
            bw_session = self._bw_session_cli_dict[lookup_key]
        
        # Step 5: Read secret value and return it
        # bw get (item|username|password|uri|totp|exposed|attachment|folder|collection|organization|org-collection|template|fingerprint) <id> [options]
        bw_env["BW_SESSION"]=bw_session
        secret = executable_wrapper.run(["bw", "get", secret_type, secret_id])
        return [secret]

    
    def _get_tmp_home_dir(self, lookup_key: str) -> str:
        if lookup_key not in self._bw_tmp_homes_dict:
            self._bw_tmp_homes_dict[lookup_key]= tempfile.TemporaryDirectory()
        return self._bw_tmp_homes_dict[lookup_key].name

class BWConfig:
    MANDATORY_PARAMETERS = ["BW_CLIENT_ID", "BW_CLIENTSECRET", "BW_GRANT_TYPE"]

    def __init__(self, **kwargs):
        self.client_id = kwargs.get("BW_CLIENT_ID", os.getenv("BW_CLIENT_ID"))
        self.scope = kwargs.get("BW_SCOPE", os.getenv("BW_SCOPE"))
        self.grant_type = kwargs.get("BW_GRANT_TYPE", os.getenv("BW_GRANT_TYPE"))
        self.url = kwargs.get("BW_URL", os.getenv("BW_URL"))
        self.client_secret = kwargs.get("BW_CLIENTSECRET", os.getenv("BW_CLIENTSECRET"))
        missing = [
            k
            for k, v in self.__dict__.items()
            if v is None and v not in BWConfig.MANDATORY_PARAMETERS
        ]
        if missing:
            raise ValueError(
                f"Missing required configuration values: {', '.join(missing)}"
            )


class LookupModule(LookupBase):
    ALLOWED_LOOKUP_TYPES = [
        "item",
        "username",
        "password",
        "uri",
        "totp",
        "exposed",
        "attachment",
        "folder",
        "collection",
        "organization",
        "org-collection",
        "template",
        "fingerprint",
    ]

    def run(self, terms, variables=None, **kwargs):
        if len(terms) != 3:
            raise AnsibleError(
                "You must provide the type, id to lookup and the vault password"
            )
        secret_type = terms[0]
        if secret_type not in LookupModule.ALLOWED_LOOKUP_TYPES:
            raise AnsibleError(
                "You must provide a valid type between item|username|password|uri|totp|exposed|attachment|folder|collection|organization|org-collection|template|fingerprint"
            )
        secret_id = terms[1]
        vault_password = terms[2]

        # Load configuration from kwargs or fallback to environment variables
        config = BWConfig(**kwargs)

        # Variables is used to track existing sessions
        bw_cli = BitwardenCliWrapper(variables)

        return bw_cli.get_secret(
            config.url,
            config.client_id,
            config.client_secret,
            vault_password,
            secret_id,
            secret_type,
        )
