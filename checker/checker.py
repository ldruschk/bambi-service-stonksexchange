import enochecker
import secrets


class StonksExchangeChecker(enochecker.BaseChecker):
    port = 8199
    flag_count = 1
    noise_count = 1
    havoc_count = 0
    service_name = "stonksexchange"

    def putflag(self):
        sessionA = self.requests.session()
        sessionB = self.requests.session()
        self.http_session = sessionA
        (usernameA, passwordA) = self.register_user()
        self.http_session = sessionB
        (usernameB, passwordB) = self.register_user()
        self.http_session = sessionA
        r = self.http_post(route='/message', data={
            "username": usernameB,
            "message": self.flag
        })
        enochecker.utils.assert_equals(r.status_code, 302)
        self.http_session = sessionB
        r = self.http_get(route='/messages')
        enochecker.utils.assert_equals(r.status_code, 200)
        enochecker.utils.assert_in(self.flag, r.text)

        self.team_db[self.flag] = {
            "usernameA": usernameA,
            "passwordA": passwordA,
            "usernameB": usernameB,
            "passwordB": passwordB,
        }

    def getflag(self):
        vals = self.team_db[self.flag]
        usernameB = vals["usernameB"]
        passwordB = vals["passwordB"]

        self.login_user(usernameB, passwordB)
        r = self.http_get(route='/messages')
        enochecker.utils.assert_equals(r.status_code, 200)
        enochecker.utils.assert_in(self.flag, r.text)

    def putnoise(self):
        pass

    def getnoise(self):
        pass

    def havoc(self):
        pass

    def exploit(self):
        pass

    def register_user(self):
        username = secrets.token_hex(6)
        password = secrets.token_hex(8)
        response = self.http_post(route='/register', data={
            "username": username,
            "password": password,
        })
        enochecker.utils.assert_equals(response.status_code, 302)

        return (username, password)

    def login_user(self, username, password):
        response = self.http_post(route='/login', data={
            "username": username,
            "password": password,
        })
        enochecker.utils.assert_equals(response.status_code, 302)

app = StonksExchangeChecker.service

if __name__ == "__main__":
    enochecker.run(StonksExchangeChecker)
