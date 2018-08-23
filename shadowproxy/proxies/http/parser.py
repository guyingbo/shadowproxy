import re
import types
import iofree

HTTP_LINE = re.compile(b"([^ ]+) +(.+?) +(HTTP/[^ ]+)")


@iofree.parser
def http_response(namespace=None):
    ns = namespace or types.SimpleNamespace()
    head = yield from iofree.read_until(b"\r\n\r\n", return_tail=False)
    first_line, *header_lines = head.split(b"\r\n")
    ns.ver, ns.code, *status = first_line.split(None, 2)
    ns.status = status[0] if status else b""
    ns.header_lines = header_lines
    return ns


@iofree.parser
def http_request(namespace=None):
    ns = namespace or types.SimpleNamespace()
    head = yield from iofree.read_until(b"\r\n\r\n", return_tail=False)
    first_line, *header_lines = head.split(b"\r\n")
    ns.method, ns.path, ns.ver = HTTP_LINE.fullmatch(first_line).groups()
    ns.headers = dict([line.split(b": ", 1) for line in header_lines])
    return ns
