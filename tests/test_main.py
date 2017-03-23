import shadowproxy


def test_is_local():
    assert shadowproxy.is_local('127.0.0.1') is True
    assert shadowproxy.is_local('192.168.20.168') is True
