import re
import iofree

HTTP_LINE = re.compile(b"([^ ]+) +(.+?) +(HTTP/[^ ]+)")


@iofree.parser
def http_response():
    parser = yield from iofree.get_parser()
    head = yield from iofree.read_until(b"\r\n\r\n", return_tail=False)
    first_line, *header_lines = head.split(b"\r\n")
    parser.ver, parser.code, *status = first_line.split(None, 2)
    parser.status = status[0] if status else b""
    parser.header_lines = header_lines


@iofree.parser
def http_request():
    parser = yield from iofree.get_parser()
    head = yield from iofree.read_until(b"\r\n\r\n", return_tail=False)
    first_line, *header_lines = head.split(b"\r\n")
    parser.method, parser.path, parser.ver = HTTP_LINE.fullmatch(first_line).groups()
    parser.headers = dict([line.split(b": ", 1) for line in header_lines])
