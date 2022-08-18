from __future__ import annotations
import random, hmac, hashlib, datetime, time
from struct import pack, unpack
import io

MAGIC = b"\x41\x55\x54\x48"

class Authenticator:
    def __init__(self, secret: bytes = None, length: int = None, expire: int = None) -> None:
        self.__digits = "0123456789"
        self.__hashes: list[Authenticator.Hash] = []
        self.__secret: bytes = None
        self.__length = 6
        self.__expire = 30
        self.__random = random.Random()

        if secret != None: self.__secret = secret
        if length != None: self.__length = length
        if expire != None: self.__expire = expire

    def __get_timestamp(self) -> int:
        return int(datetime.datetime.now().timestamp())

    def __get_code(self, timestamp: int) -> str:
        """Get TOTP code from timestamp

        Args:
            timestamp (int): Unix timestamp (seconds from 'unix epoch')

        Returns:
            str: TOTP code
        """
        # convert timestamp to bytes
        timestamp_bytes = pack("i", timestamp)

        # calculate hmac sha256 hash for timestamp bytes
        hmac_hash = hmac.new(self.__secret, digestmod="sha256")
        hmac_hash.update(timestamp_bytes)
        hash_bytes = hmac_hash.digest()

        # convert hash to integer
        hash_value = unpack("i", hash_bytes[:4])
        
        # seed random generator
        self.__random.seed(hash_value)

        # generate totp code
        password = ""

        for _ in range(self.__length):
            password += self.__random.choice(self.__digits)

        return password

    def get_code(self) -> str:
        """Get current TOTP code

        Returns:
            str: TOTP code
        """
        return self.__get_code(self.__get_timestamp())

    def verify(self, code: str) -> bool:
        """Verify TOTP code

        Args:
            code (str): TOTP code
        """
        if code == None or (type(code) == str and len(code) == 0):
            return False

        timestamp = self.__get_timestamp()
        hash_value = hash(code)

        i = 0
        while i < len(self.__hashes):
            # check if hash is expired
            if timestamp - self.__hashes[i].time > self.__expire:
                # remove expired hash
                del self.__hashes[i]
                i -= 1
            # check if code is already used
            elif self.__hashes[i].value == hash_value:
                # code is already used
                return False

            i += 1

        # check if given code is valid
        for i in range(timestamp - self.__expire, timestamp):
            if self.__get_code(i) == code:
                # add hash to hashes collection (prevents code reuse until hash expires and is removed)
                self.__hashes.append(Authenticator.Hash(hash_value, self.__get_timestamp()))

                # code is valid
                return True
                
        return False

    def clear(self):
        """Clear hashes collection"""
        self.__hashes.clear()

    def dump(self, details: Authenticator.Details) -> bytes:
        """Dump secret to bytes

        Args:
            details (Authenticator.Details): Details associated with this secret

        Returns:
            bytes
        """
        result = bytearray(MAGIC)

        # write name
        result.extend(pack("i", len(details.name)))
        result.extend(details.name.encode(encoding="utf-8"))

        # write description
        result.extend(pack("i", len(details.description)))
        result.extend(details.description.encode(encoding="utf-8"))

        # write secret
        result.extend(pack("i", len(self.__secret)))
        result.extend(self.__secret)

        return bytes(result)

    def load(self, bytes: bytes, details: Authenticator.Details) -> bool:
        """Load secret from bytes

        Args:
            bytes (bytes): Dumped bytes
            details (Authenticator.Details): Details instance

        Returns:
            bool: _description_
        """
        with io.BytesIO(bytes) as f:
            if f.read(len(MAGIC)) == MAGIC:
                # read name
                length = unpack("i", f.read(4))[0]
                details.name = f.read(length).decode(encoding="utf-8")

                # read description
                length = unpack("i", f.read(4))[0]
                details.description = f.read(length).decode(encoding="utf-8")

                # read secret
                length = unpack("i", f.read(4))[0]
                self.__secret = f.read(length)

                return True

        return False

    @staticmethod
    def random_bytes(length: int):
        """Generate `length` random bytes"""
        return random.Random().randbytes(length)

    class Details:
        def __init__(self, name: str = None, description: str = None) -> None:
            self.__name = name
            self.__description = description

        @property
        def name(self) -> str:
            """Name associated with secret"""
            return self.__name

        @name.setter
        def name(self, value: str):
            self.__name = value

        @property
        def description(self) -> str:
            """Description associated with secret"""
            return self.__description

        @description.setter
        def description(self, value: str):
            self.__description = value

    class Hash:
        def __init__(self, value: int, time: int) -> None:
            self.__value = value
            self.__time = time

        @property
        def value(self) -> int:
            """Hash value"""
            return self.__value

        @property
        def time(self) -> int:
            """Hash time"""
            return self.__time