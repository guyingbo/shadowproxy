import types
import iofree


@iofree.parser
def http_response(namespace=None):
    ns = namespace or types.SimpleNamespace()
    head = yield from iofree.read_until(b"\r\n\r\n", return_tail=False)
    first_line = head.split(b"\r\n", 1)[0]
    ns.ver, ns.code, *status = first_line.split(None, 2)
    ns.status = status[0] if status else b""
    return ns
