import unittest
from ioc_flagger.src.indicator_checks import (
    detect_ipv4_indicator,
    detect_ipv6_indicator,
    detect_md5_indicator,
    detect_sha1_indicator,
    detect_sha256_indicator,
    detect_sha512_indicator,
    detect_email_indicator,
    detect_registry_key_indicator,
    detect_user_agent_indicator,
    detect_password_indicator,
    detect_domain_name_indicator,
    detect_url_indicator,
    detect_file_name_indicator,
    detect_file_path_indicator,
)
from ioc_flagger.src.ioc_flagger import IOCTyper


class TestDetectIPv4Indicator(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(detect_ipv4_indicator("192.168.1.1"))
        self.assertTrue(detect_ipv4_indicator("1.1.1.1"))
        self.assertTrue(detect_ipv4_indicator("255.255.255.255"))
        self.assertTrue(detect_ipv4_indicator("0.0.0.0"))

    def test_invalid_ipv4(self):
        self.assertFalse(detect_ipv4_indicator("256.256.256.256"))
        self.assertFalse(detect_ipv4_indicator("192.168.1.256"))
        self.assertFalse(detect_ipv4_indicator("192.168.1"))
        self.assertFalse(detect_ipv4_indicator("192.168.1.1.1"))
        self.assertFalse(detect_ipv4_indicator("192.168..1"))
        self.assertFalse(detect_ipv4_indicator("abc.def.gha.bcd"))
        self.assertFalse(detect_ipv4_indicator(""))

    def test_edge_cases(self):
        self.assertFalse(detect_ipv4_indicator("t192.168.2.1"))
        self.assertFalse(detect_ipv4_indicator("192.168.2.1t"))
        self.assertFalse(detect_ipv4_indicator("01.01.01.01"))
        self.assertFalse(detect_ipv4_indicator("1...1"))
        self.assertFalse(detect_ipv4_indicator(" 192.168.1.1 "))
        self.assertFalse(detect_ipv4_indicator("192.168.1.1\n"))
        self.assertFalse(detect_ipv4_indicator("\n192.168.1.1"))
        self.assertFalse(detect_ipv4_indicator("192.168.1.01"))


class TestDetectIPv6Indicator(unittest.TestCase):
    def test_valid_ipv6(self):
        self.assertTrue(
            detect_ipv6_indicator("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        )
        self.assertTrue(detect_ipv6_indicator("2001:db8::ff00:42:8329"))
        self.assertTrue(detect_ipv6_indicator("::1"))
        self.assertTrue(detect_ipv6_indicator("fe80::1ff:fe23:4567:890a"))

    def test_invalid_ipv6(self):
        self.assertFalse(detect_ipv6_indicator("fe80::1ff:fe23:4567:890a\n"))
        self.assertFalse(
            detect_ipv6_indicator("2001:db8:::ff00:42:8329")
        )  # Invalid triple colon
        self.assertFalse(
            detect_ipv6_indicator("2001:db8:ff00:42:8329")
        )  # Too few segments
        self.assertFalse(
            detect_ipv6_indicator("g001:db8::ff00:42:8329")
        )  # Invalid character
        self.assertFalse(
            detect_ipv6_indicator("2001:db8::ff00:42:832g")
        )  # Invalid last segment

    def test_edge_cases(self):
        self.assertTrue(detect_ipv6_indicator("::"))  # Only double colons
        self.assertTrue(detect_ipv6_indicator("2001:db8::"))  # Ends with double colon
        self.assertTrue(detect_ipv6_indicator("::2001:db8"))  # Starts with double colon
        self.assertFalse(detect_ipv6_indicator("abc"))  # Completely invalid string
        self.assertFalse(detect_ipv6_indicator(""))  # Empty string


class TestDetectMD5Indicator(unittest.TestCase):
    def test_valid_md5(self):
        self.assertTrue(detect_md5_indicator("d41d8cd98f00b204e9800998ecf8427e"))
        self.assertTrue(detect_md5_indicator("a5465d2c08de9349e08c942b6fb6e043"))
        self.assertTrue(detect_md5_indicator("830c5168fd46e5a82434eb53a5fba91d"))

    def test_invalid_md5(self):
        self.assertFalse(detect_md5_indicator("not-a-md5-hash"))
        self.assertFalse(
            detect_md5_indicator("830c5168fd46e5a82434eb53a5fba91")
        )  # too short
        self.assertFalse(
            detect_md5_indicator("830c5168fd46e5a82434eb53a5fba91de")
        )  # too long
        self.assertFalse(
            detect_md5_indicator("830c5168fd46e5a82434eb53a5fba91z")
        )  # invalid character

    def test_empty_string(self):
        self.assertFalse(detect_md5_indicator(""))

    def test_edge_cases(self):
        self.assertFalse(detect_md5_indicator(" " * 32))  # All spaces
        self.assertFalse(
            detect_md5_indicator("a" * 31 + " ")
        )  # 31 valid chars and a space
        self.assertFalse(detect_md5_indicator(" " + "a" * 31))  # Space at the beginning


class TestDetectSHA1Indicator(unittest.TestCase):
    def test_valid_sha1(self):
        self.assertTrue(
            detect_sha1_indicator("a9993e364706816aba3e25717850c26c9cd0d89d")
        )
        self.assertTrue(
            detect_sha1_indicator("A9993E364706816ABA3E25717850C26C9CD0D89D")
        )
        self.assertTrue(
            detect_sha1_indicator("abcdef1234567890abcdef1234567890abcdef12")
        )
        self.assertTrue(
            detect_sha1_indicator("ABCDEF1234567890ABCDEF1234567890ABCDEF12")
        )

    def test_invalid_sha1_length(self):
        self.assertFalse(
            detect_sha1_indicator("a9993e364706816aba3e25717850c26c9cd0d89")
        )
        self.assertFalse(
            detect_sha1_indicator("a9993e364706816aba3e25717850c26c9cd0d89de")
        )
        self.assertFalse(
            detect_sha1_indicator("abcdef1234567890abcdef1234567890abcdef")
        )
        self.assertFalse(
            detect_sha1_indicator("abcdef1234567890abcdef1234567890abcdef123")
        )

    def test_invalid_sha1_characters(self):
        self.assertFalse(
            detect_sha1_indicator("z9993e364706816aba3e25717850c26c9cd0d89d")
        )
        self.assertFalse(
            detect_sha1_indicator("a9993e364706816aba3e25717850c26c9cd0d89g")
        )
        self.assertFalse(
            detect_sha1_indicator("12345@67#9012345678901234567890123412345")
        )
        self.assertFalse(
            detect_sha1_indicator("12345!6789012345678901234567890123412345")
        )

    def test_empty(self):
        self.assertFalse(detect_sha1_indicator(""))


class TestDetectSHA256Indicator(unittest.TestCase):
    def test_valid_sha256(self):
        valid_hashes = [
            "6c10d5e196425414264c7c5674be05c59f9d394c54fb1d8afaf49ce94da636c8",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ]
        for hash_value in valid_hashes:
            self.assertTrue(detect_sha256_indicator(hash_value))

    def test_invalid_sha256(self):
        invalid_hashes = [
            "12345",  # Too short
            "z" * 64,  # Invalid characters
            "6c10d5e196425414264c7c5674be05c59f9d394c54fb1d8afaf49ce94da636c",  # One char short
            "6c10d5e196425414264c7c5674be05c59f9d394c54fb1d8afaf49ce94da636c88",  # One char too long
            "6c10d5e196425414264c7c5674be05c59f9d394c54fb1d8afaf49ce94da636cX",  # Ends with invalid character
        ]
        for hash_value in invalid_hashes:
            self.assertFalse(detect_sha256_indicator(hash_value))

    def test_edge_cases(self):
        edge_case_values = [
            "",  # Empty string
            " " * 64,  # Only whitespace
            "abcdef" * 10,  # Repeated pattern but insufficient length
        ]
        for case in edge_case_values:
            self.assertFalse(detect_sha256_indicator(case))


class TestDetectSHA512Indicator(unittest.TestCase):
    def test_valid_sha512(self):
        self.assertTrue(
            detect_sha512_indicator(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            )
        )

    def test_invalid_length_sha512(self):
        self.assertFalse(
            detect_sha512_indicator(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3"
            )
        )  # 127 chars
        self.assertFalse(
            detect_sha512_indicator(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3ee"
            )
        )  # 129 chars

    def test_invalid_characters_sha512(self):
        self.assertFalse(
            detect_sha512_indicator(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3z"
            )
        )  # 'z' is invalid

    def test_empty_string(self):
        self.assertFalse(detect_sha512_indicator(""))

    def test_whitespace_in_sha512(self):
        self.assertFalse(
            detect_sha512_indicator(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce "
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            )
        )  # Space included


class TestDetectEmailIndicator(unittest.TestCase):
    def test_valid_emails(self):
        self.assertTrue(detect_email_indicator("test@example.com"))
        self.assertTrue(detect_email_indicator("user.name+tag+sorting@example.co.uk"))
        self.assertTrue(detect_email_indicator("x@domain.com"))
        self.assertTrue(detect_email_indicator("user123@sub.domain.org"))
        self.assertTrue(
            detect_email_indicator("test.email.with+symbol@domain-name.org")
        )

    def test_invalid_emails(self):
        self.assertFalse(detect_email_indicator("@example.com"))
        self.assertFalse(detect_email_indicator("plainaddress"))
        self.assertFalse(detect_email_indicator("missing@domain"))
        self.assertFalse(detect_email_indicator("username@."))
        self.assertFalse(detect_email_indicator("username@domain..com"))

    def test_empty_string(self):
        self.assertFalse(detect_email_indicator(""))

    def test_edge_cases(self):
        self.assertTrue(detect_email_indicator("a@b.com"))
        self.assertFalse(detect_email_indicator("a@b..com"))
        self.assertFalse(detect_email_indicator("a@.b.com"))
        self.assertFalse(detect_email_indicator("a@b@c.com"))

    def test_emails_with_special_characters(self):
        self.assertTrue(detect_email_indicator("_@example.com"))
        self.assertTrue(detect_email_indicator("example@sub-domain.com"))
        self.assertTrue(detect_email_indicator("example-123@domain.org"))
        self.assertTrue(detect_email_indicator("example!@domain.com"))
        self.assertFalse(detect_email_indicator("example@domain!com"))


class TestDetectRegistryKeyIndicator(unittest.TestCase):
    def test_valid_registry_key(self):
        self.assertTrue(
            detect_registry_key_indicator(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion"
            )
        )
        self.assertTrue(
            detect_registry_key_indicator("HKEY_CURRENT_USER\\Software\\Classes")
        )
        self.assertTrue(detect_registry_key_indicator("HKEY_CLASSES_ROOT\\.txt"))
        self.assertTrue(detect_registry_key_indicator("HKLM\\Software\\Microsoft"))
        self.assertTrue(
            detect_registry_key_indicator("HKCU\\Software\\Classes\\Applications")
        )
        self.assertTrue(detect_registry_key_indicator("HKCR\\.docx"))
        self.assertTrue(detect_registry_key_indicator("HKU\\.DEFAULT\\Software"))
        self.assertTrue(
            detect_registry_key_indicator("HKCC\\System\\CurrentControlSet")
        )
        self.assertTrue(detect_registry_key_indicator("HKEY_LOCAL_MACHINE"))
        self.assertTrue(detect_registry_key_indicator("HKCU"))

    def test_invalid_registry_key(self):
        self.assertFalse(
            detect_registry_key_indicator(
                "HKEY_LOCAL_MACHINE/Software/Microsoft/Windows/CurrentVersion"
            )
        )
        self.assertFalse(detect_registry_key_indicator("C:\\Windows\\System32"))
        self.assertFalse(detect_registry_key_indicator("HKEY_LOCAL_MACHINE<xyz>"))
        self.assertFalse(
            detect_registry_key_indicator("INVALID_KEY\\Software\\Microsoft")
        )
        self.assertFalse(
            detect_registry_key_indicator("HKEY_LOCAL_MACHINE\\Software:Invalid<Chars>")
        )
        self.assertFalse(detect_registry_key_indicator("HKCU\\Software\\|Microsoft"))

    def test_edge_cases(self):
        self.assertFalse(detect_registry_key_indicator(""))
        self.assertFalse(detect_registry_key_indicator("\\Software\\Microsoft"))
        self.assertFalse(detect_registry_key_indicator("HKCU\\\\"))
        self.assertTrue(detect_registry_key_indicator("HKEY_USERS\\.DEFAULT"))


class TestDetectUserAgentIndicator(unittest.TestCase):

    def test_valid_user_agent(self):
        self.assertTrue(
            detect_user_agent_indicator(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
            )
        )
        self.assertTrue(detect_user_agent_indicator("curl/7.64.1"))
        self.assertTrue(detect_user_agent_indicator("PostmanRuntime/7.26.10"))

    def test_invalid_user_agent(self):
        self.assertFalse(detect_user_agent_indicator("Invalid /User Agent String"))
        self.assertFalse(detect_user_agent_indicator("   "))
        self.assertFalse(detect_user_agent_indicator("/5.0 Mozilla"))
        self.assertFalse(detect_user_agent_indicator("fake.name"))
        self.assertFalse(detect_user_agent_indicator("password123"))
        self.assertFalse(detect_user_agent_indicator("www.domain.com"))
        self.assertFalse(detect_user_agent_indicator("fake.exe"))
        self.assertFalse(detect_user_agent_indicator("C:\\\\fake\\\\fake.exe"))
        self.assertFalse(detect_user_agent_indicator("/fake/fake.exe"))

    def test_edge_case_user_agent(self):
        self.assertTrue(detect_user_agent_indicator("Tool/1.0"))
        self.assertFalse(detect_user_agent_indicator(""))
        self.assertTrue(
            detect_user_agent_indicator(
                "CustomUserAgent123/4.5.6 (Some Comment) AnotherTool/1.2.3"
            )
        )
        self.assertFalse(detect_user_agent_indicator("RandomTextWithoutSlashOrNumber"))


class TestDetectPasswordIndicator(unittest.TestCase):
    def test_valid_password(self):
        self.assertTrue(detect_password_indicator("password123"))
        self.assertTrue(detect_password_indicator("qwerty"))
        self.assertTrue(detect_password_indicator("letmein"))

    def test_invalid_password(self):
        self.assertFalse(detect_password_indicator("randominput"))
        self.assertFalse(detect_password_indicator("notapassword"))
        self.assertFalse(detect_password_indicator("thereisnowaythisisinrockyou"))

    def test_empty_input(self):
        self.assertFalse(detect_password_indicator(""))


class TestDetectDomainNameIndicator(unittest.TestCase):
    def test_valid_domain_names(self):
        self.assertTrue(detect_domain_name_indicator("example.com"))
        self.assertTrue(detect_domain_name_indicator("sub.example.co.uk"))
        self.assertTrue(detect_domain_name_indicator("my-domain.org"))

    def test_invalid_domain_names(self):
        self.assertFalse(detect_domain_name_indicator("example"))
        self.assertFalse(detect_domain_name_indicator("example..com"))
        self.assertFalse(detect_domain_name_indicator(".example.com"))
        self.assertFalse(detect_domain_name_indicator("example.com."))
        self.assertFalse(detect_domain_name_indicator("example,com"))
        self.assertFalse(detect_domain_name_indicator("example_com"))
        self.assertFalse(detect_domain_name_indicator("malware.py"))
        self.assertFalse(detect_domain_name_indicator("malware.zip"))

    def test_edge_cases(self):
        self.assertFalse(detect_domain_name_indicator(""))
        self.assertFalse(detect_domain_name_indicator(" "))
        self.assertFalse(detect_domain_name_indicator("a.b"))
        self.assertFalse(detect_domain_name_indicator("a.-b.com"))
        self.assertFalse(detect_domain_name_indicator("-a.b.com"))
        self.assertTrue(detect_domain_name_indicator("a.b.com"))

    def test_valid_top_level_domains(self):
        self.assertTrue(detect_domain_name_indicator("example.ai"))
        self.assertTrue(detect_domain_name_indicator("example.xyz"))
        self.assertTrue(detect_domain_name_indicator("example.gov"))
        self.assertTrue(detect_domain_name_indicator("subdomain.example.museum"))
        self.assertFalse(detect_domain_name_indicator("example.invalidtld"))


class TestDetectUrlIndicator(unittest.TestCase):

    def test_valid_http_url(self):
        self.assertTrue(detect_url_indicator("http://www.example.com"))
        self.assertTrue(detect_url_indicator("http://example.org/page"))
        self.assertTrue(detect_url_indicator("http://subdomain.example.co.uk/test"))
        self.assertTrue(detect_url_indicator("http://subdomain.example.co.uk/test.exe"))

    def test_valid_https_url(self):
        self.assertTrue(detect_url_indicator("https://example.com"))
        self.assertTrue(detect_url_indicator("https://sub.example.net/page"))
        self.assertTrue(detect_url_indicator("https://www.example.io/path/to/resource"))

    def test_invalid_url_missing_scheme(self):
        self.assertFalse(detect_url_indicator("www.example.com"))
        self.assertFalse(detect_url_indicator("example.com"))

    def test_invalid_url_invalid_scheme(self):
        self.assertFalse(detect_url_indicator("ftp://example.com"))
        self.assertFalse(detect_url_indicator("htp://example.com"))

    def test_invalid_url_incorrect_format(self):
        self.assertFalse(detect_url_indicator("http:///example.com"))
        self.assertFalse(detect_url_indicator("http://.com"))
        self.assertFalse(detect_url_indicator("http://example"))

    def test_url_with_invalid_tld(self):
        self.assertFalse(detect_url_indicator("http://example.invalidtld"))
        self.assertFalse(detect_url_indicator("https://web.pagewrong"))
        self.assertFalse(
            detect_url_indicator("https://www.sub.example.fak/path/to/resource.exe")
        )

    def test_edge_cases(self):
        self.assertFalse(detect_url_indicator(""))
        self.assertFalse(detect_url_indicator("http://"))
        self.assertFalse(detect_url_indicator("https://"))


class TestDetectFileNameIndicator(unittest.TestCase):
    def test_valid_file_names(self):
        self.assertTrue(detect_file_name_indicator("example.txt"))
        self.assertTrue(detect_file_name_indicator("document.pdf"))
        self.assertTrue(detect_file_name_indicator("archive.tar.gz"))
        self.assertTrue(detect_file_name_indicator("file123.docx"))

    def test_invalid_file_names(self):
        self.assertFalse(detect_file_name_indicator("example"))
        self.assertFalse(detect_file_name_indicator("file/name.txt"))
        self.assertFalse(detect_file_name_indicator("document:<pdf>"))
        self.assertFalse(detect_file_name_indicator("invalid|file.exe"))
        self.assertFalse(detect_file_name_indicator(".hiddenfile"))
        self.assertFalse(
            detect_file_name_indicator("file_with_invalid_extension.toolongext")
        )

    def test_edge_cases(self):
        self.assertTrue(detect_file_name_indicator("a.b"))
        self.assertTrue(detect_file_name_indicator("filename.x"))
        self.assertTrue(detect_file_name_indicator("file name.txt"))
        self.assertFalse(detect_file_name_indicator("file\nname.txt"))
        self.assertFalse(detect_file_name_indicator(""))


class TestDetectFilePathIndicator(unittest.TestCase):

    def test_valid_windows_paths(self):
        self.assertTrue(
            detect_file_path_indicator("C:\\Users\\User\\Documents\\file.txt")
        )
        self.assertTrue(
            detect_file_path_indicator("C:\\Program Files\\Application\\app.exe")
        )
        self.assertTrue(detect_file_path_indicator("D:\\data\\subfolder\\file.ext"))

    def test_valid_linux_paths(self):
        self.assertTrue(detect_file_path_indicator("/home/user/docs/file.txt"))
        self.assertTrue(detect_file_path_indicator("/usr/local/bin/executable"))
        self.assertTrue(detect_file_path_indicator("/etc/config/settings.cfg"))

    def test_invalid_paths(self):
        self.assertFalse(
            detect_file_path_indicator(
                "invalid_path_without_drive_letter\\folder\\file.txt"
            )
        )
        self.assertFalse(
            detect_file_path_indicator("C:/mixed\\slashes\\are\\not\\allowed")
        )
        self.assertFalse(
            detect_file_path_indicator("/home/user//double_slash/file.txt")
        )
        self.assertFalse(
            detect_file_path_indicator("C:\\folder_with_invalid|character\\file.txt")
        )
        self.assertFalse(detect_file_path_indicator(""))

    def test_edge_cases(self):
        self.assertFalse(
            detect_file_path_indicator("\\\\network_share\\folder\\file.txt")
        )
        self.assertFalse(detect_file_path_indicator("C:\\"))
        self.assertFalse(detect_file_path_indicator("/"))
        self.assertFalse(detect_file_path_indicator(":::::"))


class TestIOCTyper(unittest.TestCase):
    def test_fang_indicator_conversion(self):
        typer = IOCTyper("")
        self.assertEqual(
            typer.fang_indicator("hxxp://example.com"), "http://example.com"
        )
        self.assertEqual(
            typer.fang_indicator("hxxps://example.com"), "https://example.com"
        )
        self.assertEqual(typer.fang_indicator("(example).com"), "example.com")
        self.assertEqual(typer.fang_indicator("[example].com"), "example.com")
        self.assertEqual(typer.fang_indicator("{example}.com"), "example.com")
        self.assertEqual(typer.fang_indicator("\nexample,com\r"), "example.com")

    def test_dynamically_interpret_type_ipv4(self):
        typer = IOCTyper("")
        self.assertEqual(typer.dynamically_interpret_type("192.168.0.1"), "IPv4")
        self.assertEqual(typer.dynamically_interpret_type("8.8.8.8"), "IPv4")

    def test_dynamically_interpret_type_ipv6(self):
        typer = IOCTyper("")
        self.assertEqual(
            typer.dynamically_interpret_type("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            "IPv6",
        )
        self.assertEqual(typer.dynamically_interpret_type("::1"), "IPv6")

    def test_dynamically_interpret_type_hashes(self):
        typer = IOCTyper("")
        self.assertEqual(
            typer.dynamically_interpret_type("d41d8cd98f00b204e9800998ecf8427e"), "MD5"
        )
        self.assertEqual(
            typer.dynamically_interpret_type(
                "da39a3ee5e6b4b0d3255bfef95601890afd80709"
            ),
            "SHA1",
        )
        self.assertEqual(
            typer.dynamically_interpret_type(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
            "SHA256",
        )
        self.assertEqual(
            typer.dynamically_interpret_type(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            ),
            "SHA512",
        )

    def test_dynamically_interpret_type_email(self):
        typer = IOCTyper("")
        self.assertEqual(
            typer.dynamically_interpret_type("example@example.com"), "Email"
        )

    def test_dynamically_interpret_type_registry_key(self):
        typer = IOCTyper("")
        self.assertEqual(
            typer.dynamically_interpret_type(r"HKLM\Software\Microsoft"), "Registry Key"
        )

    def test_dynamically_interpret_type_user_agent(self):
        typer = IOCTyper("")
        self.assertEqual(
            typer.dynamically_interpret_type(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            ),
            "User Agent",
        )

    def test_dynamically_interpret_type_password(self):
        typer = IOCTyper("")
        self.assertEqual(typer.dynamically_interpret_type("P@ssw0rd!"), "Password")

    def test_dynamically_interpret_type_domain_name(self):
        typer = IOCTyper("")
        self.assertEqual(typer.dynamically_interpret_type("example.com"), "Domain Name")

    def test_dynamically_interpret_type_file_name(self):
        typer = IOCTyper("")
        self.assertEqual(typer.dynamically_interpret_type("example.txt"), "File Name")

    def test_dynamically_interpret_type_file_path(self):
        typer = IOCTyper("")
        self.assertEqual(
            typer.dynamically_interpret_type(r"C:\Users\example\file.txt"), "File Path"
        )

    def test_dynamically_interpret_type_fall_through(self):
        typer = IOCTyper("")
        self.assertEqual(typer.dynamically_interpret_type("unknown_value"), "Unknown")

    def test_ioc_type_manual_initialization(self):
        typer = IOCTyper("192.168.0.1", ioc_type="CustomType")
        self.assertEqual(typer.ioc_value, "192.168.0.1")
        self.assertEqual(typer.ioc_type, "CustomType")

    def test_ioc_type_dynamic_initialization(self):
        typer = IOCTyper("192.168.0.1")
        self.assertEqual(typer.ioc_value, "192.168.0.1")
        self.assertEqual(typer.ioc_type, "IPv4")


if __name__ == "__main__":
    unittest.main()
