import enochecker
import secrets


class StonksExchangeChecker(enochecker.BaseChecker):
    port = 8199
    flag_variants = 1
    noise_variants = 2
    havoc_variants = 0
    service_name = "stonksexchange"

    def putflag(self):
        if self.variant_id > 0:
            raise enochecker.BrokenCheckerException(
                f"invalid variant_id in putflag: {self.variant_id}"
            )

        sessionA = self.requests.session()
        sessionB = self.requests.session()
        self.http_session = sessionA
        self.register_user()
        self.http_session = sessionB
        (usernameB, passwordB) = self.register_user()

        self.http_session = sessionA
        self.send_message(usernameB, self.flag)

        self.chain_db = {
            "username": usernameB,
            "password": passwordB,
        }

    def getflag(self):
        if self.variant_id > 0:
            raise enochecker.BrokenCheckerException(
                f"invalid variant_id in putflag: {self.variant_id}"
            )

        vals = self.chain_db
        username = vals["username"]
        password = vals["password"]

        self.login_user(username, password)
        self.receive_message(self.flag)

    def putnoise(self):
        if self.variant_id == 0:
            # send noise to different user
            sessionA = self.requests.session()
            sessionB = self.requests.session()
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
            raise enochecker.BrokenCheckerException(
                f"invalid variant_id in putnoise: {self.variant_id}"
            )

    def getnoise(self):
        if self.variant_id == 0:
            # send noise to different user
            vals = self.chain_db
            username = vals["username"]
            password = vals["password"]

            self.login_user(username, password)
            self.receive_message(self.noise)
        elif self.variant_id == 1:
            vals = self.chain_db
            username = vals["username"]
            password = vals["password"]

            self.login_user(username, password)
            self.receive_message(self.noise)
        else:
            raise enochecker.BrokenCheckerException(
                f"invalid variant_id in getnoise: {self.variant_id}"
            )

    def havoc(self):
        raise enochecker.BrokenCheckerException(
            f"invalid variant_id in havoc: {self.variant_id}"
        )

    def exploit(self):
        pass

    def send_message(self, username: str, message: str):
        r = self.http_post(
            route="/message",
            data={
                "username": username,
                "message": message,
            },
        )
        enochecker.utils.assert_equals(r.status_code, 302)

    def receive_message(self, message: str):
        r = self.http_get(route="/messages")
        enochecker.utils.assert_equals(r.status_code, 200)
        enochecker.utils.assert_in(message, r.text)

    def register_user(self):
        username = secrets.token_hex(6)
        password = secrets.token_hex(8)
        response = self.http_post(
            route="/register",
            data={
                "username": username,
                "password": password,
            },
        )
        enochecker.utils.assert_equals(response.status_code, 302)

        return (username, password)

    def login_user(self, username, password):
        response = self.http_post(
            route="/login",
            data={
                "username": username,
                "password": password,
            },
        )
        enochecker.utils.assert_equals(response.status_code, 302)


app = StonksExchangeChecker.service

if __name__ == "__main__":
    enochecker.run(StonksExchangeChecker)
