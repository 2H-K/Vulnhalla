from src.utils.path_normalizer import PathNormalizer


def test_normalize_source_location_prefix_windows():
    assert PathNormalizer.normalize_source_location_prefix(
        "C:\\Users\\me\\proj"
    ) == "C_/Users/me/proj"


def test_normalize_source_location_prefix_linux():
    assert PathNormalizer.normalize_source_location_prefix(
        "/home/me/proj"
    ) == "home/me/proj"


def test_build_zip_path_relative_windows():
    colon, underscore = PathNormalizer.build_zip_path(
        "C:\\Users\\me\\proj",
        "relative:///src/main.c"
    )
    assert colon == "C:/Users/me/proj/src/main.c"
    assert underscore == "C_/Users/me/proj/src/main.c"


def test_build_zip_path_relative_linux():
    colon, underscore = PathNormalizer.build_zip_path(
        "/home/me/proj",
        "relative:///src/main.c"
    )
    assert colon == "home/me/proj/src/main.c"
    assert underscore == "home/me/proj/src/main.c"


def test_build_zip_path_absolute_windows():
    colon, underscore = PathNormalizer.build_zip_path(
        "C:\\Users\\me\\proj",
        "file:///C:/Users/me/proj/src/main.c"
    )
    assert colon == "C:/Users/me/proj/src/main.c"
    assert underscore == "C_/Users/me/proj/src/main.c"


def test_build_zip_path_absolute_linux():
    colon, underscore = PathNormalizer.build_zip_path(
        "/home/me/proj",
        "file:///home/me/proj/src/main.c"
    )
    assert colon == "home/me/proj/src/main.c"
    assert underscore == "home/me/proj/src/main.c"
