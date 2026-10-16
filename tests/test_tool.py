import unittest
import tool

class BehaviorTests(unittest.TestCase):
    def test_case_0(self):
        self.assertEqual([x["kind"] for x in tool.analyze({'rules': []})], [])

    def test_case_1(self):
        self.assertEqual([x["kind"] for x in tool.analyze({'rules': [{'action': 'deny'}, {'action': 'allow', 'source': '192.0.2.0/24', 'ports': 443}]})], ['shadowed'])

    def test_case_2(self):
        self.assertEqual([x["kind"] for x in tool.analyze({'rules': [], 'packets': [{'source': '192.0.2.1', 'port': 443, 'protocol': 'tcp'}]})], ['decision'])

    def test_missing_required_input(self):
        with self.assertRaises((KeyError, ValueError, TypeError)):
            tool.analyze({})


    def test_first_match_wins(self):
        result=tool.analyze({'rules':[{'action':'deny'},{'action':'allow','ports':443}],'packets':[{'source':'192.0.2.1','port':443,'protocol':'tcp'}]})
        self.assertEqual(result[-1]['action'],'deny')
        self.assertEqual(result[-1]['rule'],0)
    def test_ipv6_and_protocol(self):
        result=tool.analyze({'rules':[{'action':'allow','source':'2001:db8::/32','ports':443,'protocol':'tcp'}],'packets':[{'source':'2001:db8::1','port':443,'protocol':'udp'}]})
        self.assertEqual(result[-1]['action'],'deny')
    def test_invalid_range_rejected(self):
        with self.assertRaises(ValueError): tool.analyze({'rules':[{'action':'allow','ports':[100,1]}]})
