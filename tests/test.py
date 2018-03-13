import unittest
from flask import json


class MyTestCase(unittest.TestCase):
    def test_something(self):
        msg = {'to':'management', 'property':'debuglevel'}
        s = json.dumps(msg)
        self.assertEqual(True, False)


if __name__ == '__main__':
    unittest.main()
