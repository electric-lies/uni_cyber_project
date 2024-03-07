from context import server

# from server.protocol import parse_meesage_content
import unittest


class TestStringMethods(unittest.TestCase):
    def test_upper(self):
        client_id = "0123456789abcdef0123456789abcdef"
        version = 1
        code = 1025
        paylod_size = 255
        message = (
            bytes.fromhex(client_id)
            + version.to_bytes(1)
            + code.to_bytes(2)
            + paylod_size.to_bytes(4)
        )

        parsed_message = server.messages.parse_message_header(message)

        self.assertEqual(parsed_message.client_id, client_id)
        self.assertEqual(parsed_message.version, version)
        self.assertEqual(parsed_message.code.value, code)
        self.assertEqual(parsed_message.payload_size, paylod_size)

    # def test_isupper(self):
    #   self.assertTrue('FOO'.isupper())
    #   self.assertFalse('Foo'.isupper())

    # def test_split(self):
    #    s = 'hello world'
    #    self.assertEqual(s.split(), ['hello', 'world'])
    #    # check that s.split fails when the separator is not a string
    #    with self.assertRaises(TypeError):
    #       s.split(2)


if __name__ == "__main__":
    unittest.main()
