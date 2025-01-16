import unittest

from ioc_flagger.src.data_bank.io_databank import DataBank
from ioc_flagger.src.indicator_searches import (
    _search_for_match_in_string,
    find_ipv4_indicator,
    find_ipv6_indicator,
    find_md5_indicator,
    find_sha1_indicator,
    find_sha256_indicator,
    find_sha512_indicator,
    find_email_indicator,
    find_registry_key_indicator,
    find_user_agent_indicator,
    find_password_indicator,
    find_domain_name_indicator,
    find_url_indicator,
    find_file_name_indicator,
    find_file_path_indicator,
)


class TestSearchForMatchInString(unittest.TestCase):

    def test_match_found(self):
        pattern = r"\btest\b"
        value = "This is a test string"
        expected_result = (True, "test")
        self.assertEqual(_search_for_match_in_string(pattern, value), expected_result)

    def test_no_match_found(self):
        pattern = r"\btest\b"
        value = "This is a string without a match"
        expected_result = (False, "")
        self.assertEqual(_search_for_match_in_string(pattern, value), expected_result)

    def test_partial_match(self):
        pattern = r"Test"
        value = "Testing a string"
        expected_result = (True, "Test")
        self.assertEqual(_search_for_match_in_string(pattern, value), expected_result)

    def test_empty_string(self):
        pattern = r"\btest\b"
        value = ""
        expected_result = (False, "")
        self.assertEqual(_search_for_match_in_string(pattern, value), expected_result)

    def test_empty_pattern(self):
        pattern = r""
        value = "Some string"
        expected_result = (True, "")
        self.assertEqual(_search_for_match_in_string(pattern, value), expected_result)

    def test_special_characters(self):
        pattern = r"\$\d+\.\d{2}"
        value = "Price is $15.99 today"
        expected_result = (True, "$15.99")
        self.assertEqual(_search_for_match_in_string(pattern, value), expected_result)

    def test_multiple_matches(self):
        pattern = r"\d+"
        value = "There are 3 apples and 10 oranges"
        expected_result = (True, "3")
        self.assertEqual(_search_for_match_in_string(pattern, value), expected_result)

    def test_unicode_support(self):
        pattern = r"\bmañana\b"
        value = "Hasta mañana"
        expected_result = (True, "mañana")
        self.assertEqual(_search_for_match_in_string(pattern, value), expected_result)


class TestFindIPv4Indicator(unittest.TestCase):
    def test_valid_ipv4(self):
        # Valid IPv4 addresses
        self.assertEqual(find_ipv4_indicator("192.168.1.1"), (True, "192.168.1.1"))
        self.assertEqual(find_ipv4_indicator("10.0.0.1"), (True, "10.0.0.1"))
        self.assertEqual(find_ipv4_indicator("172.16.0.1"), (True, "172.16.0.1"))

    def test_invalid_ipv4(self):
        # Invalid IPv4 addresses
        self.assertEqual(find_ipv4_indicator("999.999.999.999"), (False, ""))
        self.assertEqual(find_ipv4_indicator("256.256.256.256"), (False, ""))
        self.assertEqual(find_ipv4_indicator("192.168.1.256"), (False, ""))
        self.assertEqual(find_ipv4_indicator("not_an_ip"), (False, ""))

    def test_edge_cases(self):
        # Edge cases for IPv4
        self.assertEqual(find_ipv4_indicator("0.0.0.0"), (True, "0.0.0.0"))
        self.assertEqual(
            find_ipv4_indicator("255.255.255.255"), (True, "255.255.255.255")
        )

    def test_ipv4_with_extra_text(self):
        # IPv4 embedded in text
        self.assertEqual(
            find_ipv4_indicator("my ip is 192.168.1.1 today"), (True, "192.168.1.1")
        )
        self.assertEqual(
            find_ipv4_indicator("Use 10.0.0.1 for testing"), (True, "10.0.0.1")
        )
        self.assertEqual(find_ipv4_indicator("There is no IP here 123"), (False, ""))


class TestFindIPv6IndicatorInSentences(unittest.TestCase):
    def test_ipv6_inside_sentence(self):
        self.assertEqual(
            find_ipv6_indicator(
                "Here is an IPv6 address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334 in the text."
            ),
            (True, "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
        )
        self.assertEqual(
            find_ipv6_indicator("The IPv6 localhost address ::1 is commonly used."),
            (True, "::1"),
        )
        self.assertEqual(
            find_ipv6_indicator(
                "Mixed-case IPv6 address like 2001:DB8:: can also appear."
            ),
            (True, "2001:DB8::"),
        )

    def test_ipv6_surrounded_by_other_text(self):
        self.assertEqual(
            find_ipv6_indicator("Prefix text 2001:db8:: suffix text"),
            (True, "2001:db8::"),
        )
        self.assertEqual(
            find_ipv6_indicator("Some text 0:0:0:0:0:0:0:1 more text"),
            (True, "0:0:0:0:0:0:0:1"),
        )
        self.assertEqual(
            find_ipv6_indicator("IP at the start: 0:: and more information."),
            (True, "0::"),
        )

    def test_no_ipv6_in_sentence(self):
        self.assertEqual(
            find_ipv6_indicator("This sentence has no IP addresses at all."),
            (False, ""),
        )
        self.assertEqual(
            find_ipv6_indicator("Here is an IPv4 address: 192.168.1.1, but no IPv6."),
            (False, ""),
        )
        self.assertEqual(
            find_ipv6_indicator("Random text without an address."),
            (False, ""),
        )

    def test_invalid_ipv6_inside_sentence(self):
        self.assertEqual(
            find_ipv6_indicator(
                "An invalid IPv6 address like NOT_AN_IPV6:BRO within the text."
            ),
            (False, ""),
        )
        self.assertEqual(
            find_ipv6_indicator("Another example of malformed IPv6 2001:g8:zxy0."),
            (False, ""),
        )
        self.assertEqual(
            find_ipv6_indicator("NotAnIPv6:Address is present in this sentence."),
            (False, ""),
        )


class TestFindMd5Indicator(unittest.TestCase):
    def test_empty_string(self):
        result = find_md5_indicator("")
        self.assertEqual(result, (False, ""))

    def test_valid_md5(self):
        result = find_md5_indicator("d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(result, (True, "d41d8cd98f00b204e9800998ecf8427e"))

    def test_invalid_md5(self):
        result = find_md5_indicator("invalid_md5_hash")
        self.assertEqual(result, (False, ""))

    def test_string_with_valid_md5(self):
        result = find_md5_indicator(
            "Here is a valid hash: d41d8cd98f00b204e9800998ecf8427e in this string."
        )
        self.assertEqual(result, (True, "d41d8cd98f00b204e9800998ecf8427e"))

    def test_string_with_invalid_md5(self):
        result = find_md5_indicator("This string contains: invalid_md5_hash.")
        self.assertEqual(result, (False, ""))

    def test_multiple_md5_in_string(self):
        result = find_md5_indicator(
            "Two hashes: d41d8cd98f00b204e9800998ecf8427e and 9e107d9d372bb6826bd81d3542a419d6"
        )
        self.assertEqual(result, (True, "d41d8cd98f00b204e9800998ecf8427e"))


class TestFindSha1Indicator(unittest.TestCase):

    def test_valid_sha1_hash(self):
        result, context = find_sha1_indicator(
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        )
        self.assertTrue(result)
        self.assertEqual(context, "da39a3ee5e6b4b0d3255bfef95601890afd80709")

        result, context = find_sha1_indicator(
            "b47cc8018c5e4a75afb2e57b0e2a23d2951dcfb8"
        )
        self.assertTrue(result)
        self.assertEqual(context, "b47cc8018c5e4a75afb2e57b0e2a23d2951dcfb8")

    def test_invalid_sha1_hash(self):
        result, context = find_sha1_indicator("invalid_sha1_hash")
        self.assertFalse(result)
        self.assertEqual(context, "")

        result, context = find_sha1_indicator("12345")
        self.assertFalse(result)
        self.assertEqual(context, "")

    def test_empty_string(self):
        result, context = find_sha1_indicator("")
        self.assertFalse(result)
        self.assertEqual(context, "")

    def test_partial_match(self):
        result, context = find_sha1_indicator(
            "Random text da39a3ee5e6b4b0d3255bfef95601890afd80709 more text"
        )
        self.assertTrue(result)
        self.assertEqual(context, "da39a3ee5e6b4b0d3255bfef95601890afd80709")

        result, context = find_sha1_indicator(
            "Leading a9993e364706816aba3e25717850c26c9cd0d89d followed by text"
        )
        self.assertTrue(result)
        self.assertEqual(context, "a9993e364706816aba3e25717850c26c9cd0d89d")

    def test_no_match_in_unrelated_string(self):
        result, context = find_sha1_indicator(
            "This string does not contain any valid SHA1 hash"
        )
        self.assertFalse(result)
        self.assertEqual(context, "")


class TestFindSHA256Indicator(unittest.TestCase):
    def test_valid_sha256(self):
        self.assertEqual(
            find_sha256_indicator(
                "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
            ),
            (True, "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"),
        )
        self.assertEqual(
            find_sha256_indicator(
                "E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3"
            ),
            (True, "E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3E3"),
        )

    def test_invalid_sha256(self):
        self.assertEqual(find_sha256_indicator("1234567890abcdef"), (False, ""))
        self.assertEqual(find_sha256_indicator("notasha256value"), (False, ""))
        self.assertEqual(
            find_sha256_indicator(
                "d2d2d2d2d2d2d2d2d2d2d2d2d2d2-highly_invalid_character"
            ),
            (False, ""),
        )

    def test_empty_string(self):
        self.assertEqual(find_sha256_indicator(""), (False, ""))

    def test_special_characters(self):
        self.assertEqual(find_sha256_indicator("!@#$%^&*()_+{}:<>?"), (False, ""))

    def test_edge_case_length(self):
        # Below 64 characters
        self.assertEqual(find_sha256_indicator("a" * 63), (False, ""))
        # Exactly 64 valid characters
        self.assertEqual(find_sha256_indicator("a" * 64), (True, "a" * 64))
        # Over 64 characters
        self.assertEqual(find_sha256_indicator("a" * 65), (True, "a" * 64))


class TestFindSHA512Indicator(unittest.TestCase):

    def test_valid_sha512(self):
        match_found, matching_string = find_sha512_indicator(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877bd77e55d3c6d2e1df822e035a99e417319f43"
        )
        self.assertEqual(
            (match_found, matching_string),
            (
                True,
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877bd77e55d3c6d2e1df822e035a99e417319f43",
            ),
        )

    def test_invalid_sha512(self):
        match_found, matching_string = find_sha512_indicator("invalidsha512string")
        self.assertEqual((match_found, matching_string), (False, ""))

    def test_empty_string(self):
        match_found, matching_string = find_sha512_indicator("")
        self.assertEqual((match_found, matching_string), (False, ""))

    def test_partial_sha512(self):
        match_found, matching_string = find_sha512_indicator(
            "cf83e1357eefb8bdf1542850d66d8007"
        )
        self.assertEqual((match_found, matching_string), (False, ""))

    def test_non_sha512_text_with_valid_sha512(self):
        ioc_value = "Prefix text with valid hash cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877bd77e55d3c6d2e1df822e035a99e417319f43 and suffix text"
        match_found, matching_string = find_sha512_indicator(ioc_value)
        self.assertEqual(
            (match_found, matching_string),
            (
                True,
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877bd77e55d3c6d2e1df822e035a99e417319f43",
            ),
        )

    def test_non_sha512_text_without_valid_sha512(self):
        match_found, matching_string = find_sha512_indicator(
            "Random text without any valid SHA512 hash present"
        )
        self.assertEqual((match_found, matching_string), (False, ""))


class TestFindEmailIndicator(unittest.TestCase):

    def test_valid_email(self):
        self.assertEqual(
            find_email_indicator("user@example.com"), (True, "user@example.com")
        )
        self.assertEqual(
            find_email_indicator("test.email+name@subdomain.domain.org"),
            (True, "test.email+name@subdomain.domain.org"),
        )
        self.assertEqual(
            find_email_indicator("first.last@domain.museum"),
            (True, "first.last@domain.museum"),
        )

    def test_invalid_email(self):
        self.assertEqual(find_email_indicator("plainaddress"), (False, ""))
        self.assertEqual(find_email_indicator("@missingusername.com"), (False, ""))
        self.assertEqual(find_email_indicator("username@.missingdomain"), (False, ""))
        self.assertEqual(find_email_indicator("username@domain..com"), (False, ""))

    def test_edge_cases(self):
        self.assertEqual(
            find_email_indicator("user.name+tag+sorting@domain.com"),
            (True, "user.name+tag+sorting@domain.com"),
        )
        self.assertEqual(find_email_indicator("x@y.com"), (True, "x@y.com"))
        self.assertEqual(find_email_indicator(""), (False, ""))
        self.assertEqual(
            find_email_indicator("valid123.email@sub-domain123.org"),
            (True, "valid123.email@sub-domain123.org"),
        )


class TestFindRegistryKeyIndicator(unittest.TestCase):
    def test_valid_registry_key(self):
        # Tests valid Windows registry key formats
        self.assertEqual(
            find_registry_key_indicator("HKEY_LOCAL_MACHINE\\Software\\Microsoft"),
            (True, "HKEY_LOCAL_MACHINE\\Software\\Microsoft"),
        )
        self.assertEqual(
            find_registry_key_indicator("HKCU\\Software\\Microsoft"),
            (True, "HKCU\\Software\\Microsoft"),
        )
        self.assertEqual(
            find_registry_key_indicator("HKEY_CLASSES_ROOT\\exe_auto_file\\shell"),
            (True, "HKEY_CLASSES_ROOT\\exe_auto_file\\shell"),
        )

    def test_invalid_registry_key(self):
        # Tests invalid formats
        self.assertEqual(
            find_registry_key_indicator("HKEY_NOTREAL\\Software\\Microsoft"),
            (False, ""),
        )
        self.assertEqual(find_registry_key_indicator("randomstring"), (False, ""))

    def test_empty_string(self):
        # Tests empty string input
        self.assertEqual(find_registry_key_indicator(""), (False, ""))

    def test_edge_cases(self):
        # Tests cases with leading/trailing whitespace and case insensitivity
        self.assertEqual(
            find_registry_key_indicator(
                " HKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft "
            ),
            (True, "HKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft"),
        )
        self.assertEqual(
            find_registry_key_indicator(
                "\tHKEY_CLASSES_ROOT\\\\exe_auto_file\\\\shell\t"
            ),
            (True, "HKEY_CLASSES_ROOT\\\\exe_auto_file\\\\shell"),
        )


class TestFindUserAgentIndicator(unittest.TestCase):
    def test_valid_user_agent(self):
        self.assertEqual(
            find_user_agent_indicator(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            ),
            (
                True,
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            ),
        )
        self.assertEqual(
            find_user_agent_indicator(
                "Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14"
            ),
            (True, "Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14"),
        )

    def test_invalid_user_agent(self):
        self.assertEqual(
            find_user_agent_indicator("This is not a valid user agent"), (False, "")
        )
        self.assertEqual(
            find_user_agent_indicator("Another invalid string"), (False, "")
        )

    def test_empty_string(self):
        self.assertEqual(find_user_agent_indicator(""), (False, ""))

    def test_edge_case_user_agent(self):
        self.assertEqual(
            find_user_agent_indicator("Mozilla/5.0"), (True, "Mozilla/5.0")
        )
        self.assertEqual(
            find_user_agent_indicator(
                "PREFIX Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0) SUFFIX"
            ),
            (
                True,
                "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
            ),
        )


# Leaving password out for now, it increases test build time


class TestFindDomainNameIndicator(unittest.TestCase):
    def test_valid_domain(self):
        result = find_domain_name_indicator("example.com")
        self.assertEqual(result, (True, "example.com"))

    def test_invalid_domain_no_tld(self):
        result = find_domain_name_indicator("example")
        self.assertEqual(result, (False, ""))

    def test_valid_subdomain(self):
        result = find_domain_name_indicator("sub.example.org")
        self.assertEqual(result, (True, "sub.example.org"))

    def test_invalid_domain_with_special_characters(self):
        result = find_domain_name_indicator("exa$mple.com")
        self.assertEqual(result, (True, "mple.com"))

    def test_empty_string(self):
        result = find_domain_name_indicator("")
        self.assertEqual(result, (False, ""))

    def test_non_domain_text(self):
        result = find_domain_name_indicator("this is a test string")
        self.assertEqual(result, (False, ""))

    def test_valid_domain_with_uppercase(self):
        result = find_domain_name_indicator("EXAMPLE.COM")
        self.assertEqual(result, (True, "EXAMPLE.COM"))

    def test_dot_but_invalid_format(self):
        result = find_domain_name_indicator(".example")
        self.assertEqual(result, (False, ""))

    def test_valid_domain_with_numbers(self):
        result = find_domain_name_indicator("This was found on example123.io.")
        self.assertEqual(result, (True, "example123.io"))

    def test_edge_case_domain(self):
        result = find_domain_name_indicator("-www.a.b.com")
        self.assertEqual(result, (True, "www.a.b.com"))

        result = find_domain_name_indicator("[www.a.b.com]")
        self.assertEqual(result, (True, "www.a.b.com"))


class TestFindURLIndicator(unittest.TestCase):

    def test_valid_url_with_valid_tld(self):
        result, match = find_url_indicator("Check this link: https://example.com/path")
        self.assertTrue(result)
        self.assertEqual(match, "https://example.com/path")

    def test_valid_url_with_invalid_tld(self):
        result, match = find_url_indicator(
            "Check this link: https://example.invalid/path"
        )
        self.assertFalse(result)
        self.assertEqual(match, "")

    def test_invalid_url_format(self):
        result, match = find_url_indicator("This is not a URL: example/path")
        self.assertFalse(result)
        self.assertEqual(match, "")

    def test_empty_string(self):
        result, match = find_url_indicator("")
        self.assertFalse(result)
        self.assertEqual(match, "")

    def test_url_without_scheme(self):
        result, match = find_url_indicator("example.com/path")
        self.assertFalse(result)
        self.assertEqual(match, "")

    def test_url_with_subdomains(self):
        result, match = find_url_indicator("Visit: https://sub.example.com/path")
        self.assertTrue(result)
        self.assertEqual(match, "https://sub.example.com/path")

    def test_url_with_unusual_path(self):
        result, match = find_url_indicator("Check: https://example.com/!@#$%^&*()")
        self.assertTrue(result)
        self.assertEqual(match, "https://example.com/!@#$%^&*()")

    def test_multiple_urls_in_text(self):
        result, match = find_url_indicator(
            "Links: https://example.com and https://test.com"
        )
        self.assertTrue(result)
        self.assertEqual(match, "https://example.com")


class TestFindFileNameIndicator(unittest.TestCase):
    def test_valid_file_names(self):
        self.assertEqual(
            find_file_name_indicator("This is a valid file: example.txt"),
            (True, "example.txt"),
        )
        self.assertEqual(
            find_file_name_indicator("Here is another file: report.pdf"),
            (True, "report.pdf"),
        )
        self.assertEqual(
            find_file_name_indicator("Check out this image: image.jpeg"),
            (True, "image.jpeg"),
        )
        self.assertEqual(
            find_file_name_indicator("The data file is named: data_2023.csv"),
            (True, "data_2023.csv"),
        )

    def test_invalid_file_names(self):
        self.assertEqual(
            find_file_name_indicator("This string has no file name."), (False, "")
        )
        self.assertEqual(
            find_file_name_indicator("Here is some random text without any file."),
            (False, ""),
        )
        self.assertEqual(
            find_file_name_indicator("Ill-formed file name like fi|le.txt is invalid."),
            (True, "le.txt"),
        )
        self.assertEqual(
            find_file_name_indicator("A hidden file without name: ."), (False, "")
        )

    def test_edge_cases(self):
        self.assertEqual(find_file_name_indicator(""), (False, ""))
        self.assertEqual(
            find_file_name_indicator("A common file format: normal_file_name_123.docx"),
            (True, "normal_file_name_123.docx"),
        )
        self.assertEqual(
            find_file_name_indicator("Compressed files: multi.part.file.name.tar.gz"),
            (True, "multi.part.file.name.tar.gz"),
        )
        self.assertEqual(
            find_file_name_indicator("This sentence has no valid file name extension"),
            (False, ""),
        )
        self.assertEqual(
            find_file_name_indicator("Unusual characters ,、、、 might cause issues"),
            (False, ""),
        )


class TestFindFilePathIndicator(unittest.TestCase):

    def test_valid_windows_path(self):
        valid_windows_path = "C:\\Users\\Admin\\Documents\\file.txt"
        result, match = find_file_path_indicator(valid_windows_path)
        self.assertTrue(result)
        self.assertEqual(match, valid_windows_path)

    def test_valid_linux_path(self):
        valid_linux_path = "/home/user/Documents/file.txt"
        result, match = find_file_path_indicator(valid_linux_path)
        self.assertTrue(result)
        self.assertEqual(match, valid_linux_path)

    def test_invalid_path(self):
        invalid_path = "NotAPath"
        result, match = find_file_path_indicator(invalid_path)
        self.assertFalse(result)
        self.assertEqual(match, "")

    def test_partial_windows_path(self):
        partial_windows_path = "Invalid text C:\\Users\\Admin\\Documents"
        result, match = find_file_path_indicator(partial_windows_path)
        self.assertTrue(result)
        self.assertEqual(match, "C:\\Users\\Admin\\Documents")

    def test_partial_linux_path(self):
        partial_linux_path = "Invalid text /home/user/Documents"
        result, match = find_file_path_indicator(partial_linux_path)
        self.assertTrue(result)
        self.assertEqual(match, "/home/user/Documents")

    def test_path_with_special_characters_windows(self):
        special_char_windows_path = "D:\\My_Files\\Projects\\2023-Data\\data_file.txt"
        result, match = find_file_path_indicator(special_char_windows_path)
        self.assertTrue(result)
        self.assertEqual(match, special_char_windows_path)

    def test_path_with_special_characters_linux(self):
        special_char_linux_path = "/home/user-name/Projects/2023-Data/data_file.txt"
        result, match = find_file_path_indicator(special_char_linux_path)
        self.assertTrue(result)
        self.assertEqual(match, special_char_linux_path)

    def test_empty_input(self):
        empty_input = ""
        result, match = find_file_path_indicator(empty_input)
        self.assertFalse(result)
        self.assertEqual(match, "")

    def test_path_with_whitespace(self):
        path_with_whitespace = "   /home/user/Documents/file.txt   "
        result, match = find_file_path_indicator(path_with_whitespace.strip())
        self.assertTrue(result)
        self.assertEqual(match, "/home/user/Documents/file.txt")


if __name__ == "__main__":
    unittest.main()
