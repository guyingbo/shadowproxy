import typing

import iofree
from iofree.contrib import socks5

from .exceptions import ProtocolError


@iofree.parser
def server(auth: typing.Tuple[str, str]):
    parser = yield from iofree.get_parser()
    handshake = yield from socks5.Handshake.get_value()
    addr = socks5.Addr(1, "0.0.0.0", 0)
    if auth:
        if socks5.AuthMethod.user_auth not in handshake.methods:
            parser.respond(
                data=socks5.Reply(..., socks5.Rep.not_allowed, ..., addr).binary,
                close=True,
                exc=ProtocolError("auth method not allowed"),
            )
            return
        parser.respond(
            data=socks5.ServerSelection(..., socks5.AuthMethod.user_auth).binary
        )
        user_auth = yield from socks5.UsernameAuth.get_value()
        if (user_auth.username.encode(), user_auth.password.encode()) != auth:
            parser.respond(
                data=socks5.Reply(..., socks5.Rep.not_allowed, ..., addr).binary,
                close=True,
                exc=ProtocolError("auth failed"),
            )
            return
        parser.respond(data=socks5.UsernameAuthReply(..., ...).binary)
    else:
        parser.respond(
            data=socks5.ServerSelection(..., socks5.AuthMethod.no_auth).binary
        )
    request = yield from socks5.ClientRequest.get_value()
    assert (
        request.cmd is socks5.Cmd.connect
    ), f"only support connect command now, got {socks5.Cmd.connect!r}"
    parser.respond(result=request)
    rep = yield from iofree.wait_event()
    parser.respond(data=socks5.Reply(..., socks5.Rep(rep), ..., addr).binary)


@iofree.parser
def client(auth, target_addr):
    parser = yield from iofree.get_parser()
    parser.respond(
        data=socks5.Handshake(
            ..., [socks5.AuthMethod.no_auth, socks5.AuthMethod.user_auth]
        ).binary
    )
    server_selection = yield from socks5.ServerSelection.get_value()
    if server_selection.method not in (
        socks5.AuthMethod.no_auth,
        socks5.AuthMethod.user_auth,
    ):
        parser.respond(close=True, exc=ProtocolError("no method to choose"))
    if auth and (server_selection.method is socks5.AuthMethod.user_auth):
        parser.respond(
            data=socks5.UsernameAuth(..., auth[0].decode(), auth[1].decode()).binary
        )
        yield from socks5.UsernameAuthReply.get_value()
    parser.respond(
        data=socks5.ClientRequest(
            ..., socks5.Cmd.connect, ..., socks5.Addr.from_tuple(target_addr)
        ).binary
    )
    reply = yield from socks5.Reply.get_value()
    if reply.rep is not socks5.Rep.succeeded:
        parser.respond(close=True, exc=ProtocolError(f"bad reply: {reply}"))
    parser.respond(result=reply)


def resp():
    addr = socks5.Addr(3, "0.0.0.0", 0)
    return socks5.Reply(..., socks5.Rep.succeeded, ..., addr).binary
