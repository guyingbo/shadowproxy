import re

from iofree import schema

HTTP_LINE = re.compile(b"([^ ]+) +(.+?) +(HTTP/[^ ]+)")


class HTTPResponse(schema.BinarySchema):
    head = schema.EndWith(b"\r\n\r\n")

    def __post_init__(self):
        first_line, *header_lines = self.head.split(b"\r\n")
        self.ver, self.code, *status = first_line.split(None, 2)
        self.status = status[0] if status else b""
        self.header_lines = header_lines


class HTTPRequest(schema.BinarySchema):
    head = schema.EndWith(b"\r\n\r\n")

    def __post_init__(self):
        first_line, *header_lines = self.head.split(b"\r\n")
        self.method, self.path, self.ver = HTTP_LINE.fullmatch(first_line).groups()
        self.headers = dict([line.split(b": ", 1) for line in header_lines])
