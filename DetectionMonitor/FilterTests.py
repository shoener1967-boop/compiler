import re

NEEDLES = ["/var/jb", "/var/binpack", "/applications/cydia.app", "frida", "ssh"]

def suspicious(value: str) -> bool:
    v = value.lower()
    return any(n in v for n in NEEDLES)

def test_known_indicators_are_detected():
    assert suspicious('/var/jb/usr/bin/xyz')
    assert suspicious('/Applications/Cydia.app')
    assert suspicious('libfrida-gadget.dylib')

def test_normal_path_is_not_detected():
    assert not suspicious('/private/var/mobile/Containers/Data/Application/abc')

if __name__ == '__main__':
    tests = [test_known_indicators_are_detected, test_normal_path_is_not_detected]
    for test in tests:
        test()
    print(f'{len(tests)} tests passed')
