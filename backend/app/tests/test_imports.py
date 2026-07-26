import unittest
from app import main


class TestImports(unittest.TestCase):
    def test_import_main(self):
        self.assertTrue(hasattr(main, 'app'))


if __name__ == '__main__':
    unittest.main()
