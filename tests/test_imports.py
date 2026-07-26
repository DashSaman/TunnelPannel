from backend.app import main


def test_import_main():
    assert hasattr(main, 'app')
