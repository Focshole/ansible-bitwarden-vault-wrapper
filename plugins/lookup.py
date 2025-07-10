#!/usr/bin/env python3
import os
import re
import subprocess
import tempfile
import hashlib
import time

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
from ansible.utils.display import Display
from hashlib import sha256
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

display = Display()


class ExecutableException(Exception):
    def __init__(self, *args):
        super().__init__(*args)


class ExecutableWrapper:
    def __init__(self, env: dict[str, str]):
        self._env = env

    def run(self, command: str, **kwargs):
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
            raise ExecutableException(
                f"Command failed: '{'\' \''.join(command)}\n{e.stderr.strip()}'", e
            )


class BitwardenCliWrapper:
    VARIABLE_KEY = "BitwardenCliWrapper"

    def get_secret(
        self,
        bw_url: str,
        bw_client_id: str,
        bw_client_secret: str,
        bw_password: str,
        secret_id: str,
        secret_type: str,
    ):

        password_hash = sha256(bytes(bw_password, "utf8")).hexdigest()
        lookup_key = sha256(
            bytes(f"{bw_url}-{bw_client_id}-{bw_client_secret}-{password_hash}", "utf8")
        ).hexdigest()

        tmp_dir = tempfile.gettempdir()
        tmp_session_dir = Path(
            os.path.join(tmp_dir, "bitwarden_cli_wrapper", lookup_key)
        )
        tmp_session_file = Path(
            os.path.join(tmp_dir, "bitwarden_cli_wrapper", lookup_key, "sessionKey")
        )

        if not tmp_session_dir.exists():
            tmp_session_dir.mkdir(parents=True, exist_ok=True)

        bw_env = os.environ.copy()
        bw_env["HOME"] = tmp_session_dir
        bw_env["BW_CLIENTID"] = bw_client_id
        bw_env["BW_CLIENTSECRET"] = bw_client_secret
        executable_wrapper = ExecutableWrapper(bw_env)

        should_renew_session = False

        if not tmp_session_file.exists():
            self._initialize_bw_session_directory(executable_wrapper, bw_url)
            should_renew_session = True
        else:
            current_time = time.time()
            mod_time = os.path.getmtime(str(tmp_session_file.absolute()))
            older_than_30_mins = current_time - mod_time > 30 * 60
            should_renew_session = older_than_30_mins

        aes_password = hashlib.sha256(bw_password.encode()).digest()
        if should_renew_session:
            if tmp_session_file.exists():
                display.verbose("Locking the vault before renewing session...")
                display.verbose(executable_wrapper.run(["bw", "lock"]))

            # Step 4: Unlock vault to get session
            bw_session=self._unlock_vault(executable_wrapper, bw_env, bw_password)

            self._store_and_encrypt(aes_password,bw_session,tmp_session_file)
            
        else:
            bw_session= self._load_and_decrypt(aes_password,tmp_session_file)

        # Step 5: Read secret value and return it
        # bw get (item|username|password|uri|totp|exposed|attachment|folder|collection|organization|org-collection|template|fingerprint) <id> [options]
        bw_env["BW_SESSION"] = bw_session
        display.verbose(f"Running get {secret_type, secret_id}")
        secret = executable_wrapper.run(["bw", "get", secret_type, secret_id])
        bw_env["BW_SESSION"] = ""
        return [secret]

    def _initialize_bw_session_directory(
        self, executable_wrapper: ExecutableWrapper, bw_url: str
    ):

        display.verbose("Set url to '" + bw_url + "'")
        display.verbose(executable_wrapper.run(["bw", "config", "server", bw_url]))

        display.display("Logging in using api key...")
        # Step 2: Log in using the API key (client ID/secret)
        display.verbose(executable_wrapper.run(["bw", "login", "--apikey"]))

        # Step 3: Sync
        display.display("Syncing the vault...")
        display.verbose(executable_wrapper.run(["bw", "sync"]))

    def _unlock_vault(
        self,
        executable_wrapper: ExecutableWrapper,
        bw_env: dict[str, str],
        bw_password: str,
    ) -> str:

        bw_env["BW_PASSWORD"] = bw_password
        unlock_output = executable_wrapper.run(
            ["bw", "unlock", "--passwordenv", "BW_PASSWORD"]
        )
        bw_env["BW_PASSWORD"] = ""

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
        return bw_session
    
    def _store_and_encrypt(self, key: str, payload: str, file_path: Path):
        iv = get_random_bytes(16)

        # Encrypt using AES-256-GCM
        cipher = AES.new(key, AES.MODE_GCM, iv)
        ciphertext = cipher.encrypt(pad(payload.encode(), AES.block_size))
        # Write to file
        with open(str(file_path.absolute()), "wb") as f:
            f.write(iv + ciphertext)  # Store IV + ciphertext together
    
    def _load_and_decrypt(self, key: str, file_path: Path):

        with open(str(file_path.absolute()), "rb") as f:
            file_data = f.read()
            iv = file_data[:16]  # Extract the IV (first 16 bytes)
            ciphertext = file_data[16:]  # Rest is the ciphertext

        # Decrypt
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)



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
        start = time.perf_counter()
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
        bw_cli = BitwardenCliWrapper()

        secret = bw_cli.get_secret(
            config.url,
            config.client_id,
            config.client_secret,
            vault_password,
            secret_id,
            secret_type,
        )

        time_elapsed = time.perf_counter() - start
        display.verbose(f"Time taken to retrieve the secret: {time_elapsed:.4f}s")
        return secret
