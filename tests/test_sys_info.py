# Jason
# 2024/3/16 22:14
# jasonchujun@sina.com
# test_sys_info.py


import unittest


class TestSysInfoFunctions(unittest.TestCase):

    def test_get_os(self):
        result = get_os()
        self.assertIsInstance(result, str)

    def test_get_host_name(self):
        result = get_host_name()
        self.assertIsInstance(result, str)

    def test_get_timezone(self):
        result = get_timezone()
        self.assertIsInstance(result, str)


if __name__ == "__main__":
    unittest.main()
