#!/bin/bash/python3
#encoding: utf-8

from core import Link, Party, Crypto, Octets

import unittest


class TestOctets(unittest.TestCase):
	@classmethod
	def setUpClass(self):
		print("""Launching Octets class test...""")

	@classmethod
	def setUp(self):
		print("""\tLaunching new test:""", end=" ")

	@classmethod
	def tearDown(self):
		print("""\tTest done.""")

	@classmethod
	def tearDownClass(self):
		print("""Octets class test done.""")

	def test_get_len(self):
		print("""[get_len]""")
		num = 18446744073709551615
		expected = 8
		result = Octets.get_len(num)

		self.assertEqual(result, expected)


class TestMessage(unittest.TestCase):
	@classmethod
	def setUpClass(self):
		print("""Launching Message class test...""")

	@classmethod
	def setUp(self):
		print("""\tLaunching new test:""", end=" ")

	@classmethod
	def tearDown(self):
		print("""\tTest done.""")

	@classmethod
	def tearDownClass(self):
		print("""Message class test done.""")

	def test_get(self):
		print("""[get]""")
		m_type = Link.Message.PING
		m_origin = 1
		m_content = "test"

		expected = (m_type, m_origin, m_content)

		message = Link.Message(m_type, m_origin, m_content)

		result = message.get()

		self.assertEqual(result, expected)

	def test_eq(self):
		print("""comparison between message objects""")
		m_origin = 1
		m_type1 = Link.Message.PING
		m_type2 = Link.Message.FRAME
		m_content = "test"

		message1 = Link.Message(m_type1, m_origin, m_content)
		message2 = Link.Message(m_type1, m_origin, m_content)
		message3 = Link.Message(m_type2, m_origin, m_content)

		result = message1 == message2

		self.assertTrue(result)

	def test_eq_bad(self):
		print("""bad comparison between message objects""")
		m_origin = 1
		m_type1 = Link.Message.PING
		m_type2 = Link.Message.FRAME
		m_content = "test"

		message1 = Link.Message(m_type1, m_origin, m_content)
		message2 = Link.Message(m_type1, m_origin, m_content)
		message3 = Link.Message(m_type2, m_origin, m_content)

		result = message1 == message3

		self.assertFalse(result)

	def test_eq_not(self):
		print("""difference between message objects""")
		m_origin = 1
		m_type1 = Link.Message.PING
		m_type2 = Link.Message.FRAME
		m_content = "test"

		message1 = Link.Message(m_type1, m_origin, m_content)
		message2 = Link.Message(m_type1, m_origin, m_content)
		message3 = Link.Message(m_type2, m_origin, m_content)

		result = message1 != message3

		self.assertTrue(result)

	def test_eq_other_type(self):
		print("""comparison between message object and another type object""")
		m_origin = 1
		m_type1 = Link.Message.PING
		m_type2 = Link.Message.FRAME
		m_content = "test"

		message1 = Link.Message(m_type1, m_origin, m_content)
		message2 = Link.Message(m_type1, m_origin, m_content)
		message3 = Link.Message(m_type2, m_origin, m_content)

		result = message1 == message2

		self.assertTrue(result)

		result = message1 != 2

		self.assertTrue(result)

class TestNetworkInterface(unittest.TestCase):
	@classmethod
	def setUpClass(self):
		print("""Launching NetworkInterface class test...""")

	@classmethod
	def setUp(self):
		print("""\tLaunching new test:""", end=" ")

	@classmethod
	def tearDown(self):
		print("""\tTest done.""")

	@classmethod
	def tearDownClass(self):
		print("""NetworkInterface class test done.""")

	def test_set_channel(self):
		print("""[set_channel]""")
		ni = Link.NetworkInterface()

		channel = Link.Channel()

		result = ni.set_channel(1, channel)

		self.assertTrue(result)

	def test_set_channel_bis(self):
		print("""[set_channel] while already set channel""")
		ni = Link.NetworkInterface()

		channel = Link.Channel()

		ni.set_channel(1, channel)

		result = ni.set_channel(1, channel)

		self.assertFalse(result)

	def test_set_channel_differents(self):
		print("""[set_channel] with different channels""")
		ni = Link.NetworkInterface()

		channel1 = Link.Channel()
		channel2 = Link.Channel()

		ni.set_channel(1, channel1)

		result = ni.set_channel(2, channel2)

		self.assertTrue(result)

	def test_has_message(self):
		print("""[has_message] with simple message""")
		ni = Link.NetworkInterface()
		ni.set_recv_handler(lambda x: x)

		message = Link.Message(Link.Message.PING, 1, "test")

		ni.append(message)

		result = ni.has_message()

		self.assertTrue(result)

	def test_has_message_empty(self):
		print("""[has_message] with empty message queue""")
		ni = Link.NetworkInterface()

		expected = 0

		result = ni.has_message()

		self.assertEqual(result, expected)

	def test_has_message_multiple(self):
		print("""[has_message] with multiple messages""")
		ni = Link.NetworkInterface()
		ni.set_recv_handler(lambda x: x)

		message1 = Link.Message(Link.Message.PING, 1, "test1")
		message2 = Link.Message(Link.Message.PING, 1, "test2")

		expected = 2

		ni.append(message1)
		ni.append(message2)

		result = ni.has_message()

		self.assertEqual(result, expected)

	def test_get(self):
		print("""[get] with simple message""")
		ni = Link.NetworkInterface()
		ni.set_recv_handler(lambda x: x)

		message = Link.Message(Link.Message.PING, 1, "test")

		ni.append(message)

		result = ni.get()

		self.assertEqual(result, message)

	def test_get_multiple(self):
		print("""[get] with multiple messages""")
		ni = Link.NetworkInterface()
		ni.set_recv_handler(lambda x: x)

		message1 = Link.Message(Link.Message.PING, 1, "test1")
		message2 = Link.Message(Link.Message.PING, 1, "test2")
		expected = (message1, message2)

		ni.append(message1)
		ni.append(message2)

		result1 = ni.get()
		result2 = ni.get()
		result = (result1, result2)

		self.assertEqual(result, expected)

	def test_get_empty(self):
		print("""[get] with empty message queue""")
		ni = Link.NetworkInterface()

		expected = None

		result = ni.get()

		self.assertEqual(result, expected)

	def test_send_to(self):
		print("""[send_to]""")
		ni1 = Link.NetworkInterface()
		ni2 = Link.NetworkInterface()
		ni2.set_recv_handler(lambda x: x)

		channel = Link.Channel()
		channel.add_interface(1, ni1)
		channel.add_interface(2, ni2)

		ni1.set_channel(2, channel)
		ni2.set_channel(1, channel)

		message = Link.Message(Link.Message.PING, 1, "test")

		expected = Link.SUCCESS

		result = ni1.send_to(2, message)

		self.assertEqual(result, expected)

	def test_send_to_cutoff(self):
		print("""[send_to] on cutoff channel""")
		ni1 = Link.NetworkInterface()
		ni2 = Link.NetworkInterface()
		ni2.set_recv_handler(lambda x: x)

		channel = Link.Channel()
		channel.add_interface(1, ni1)
		channel.add_interface(2, ni2)
		channel.cutoff()

		ni1.set_channel(2, channel)
		ni2.set_channel(1, channel)

		message = Link.Message(Link.Message.PING, 1, "test")

		expected = Link.CUTOFF

		result = ni1.send_to(2, message)

		self.assertEqual(result, expected)


class TestChannel(unittest.TestCase):
	@classmethod
	def setUpClass(self):
		print("""Launching Channel class test...""")
		self.ni1 = Link.NetworkInterface()
		self.ni2 = Link.NetworkInterface()
		self.ni2.set_recv_handler(lambda x: x)

	@classmethod
	def setUp(self):
		print("""\tLaunching new test:""", end=" ")

	@classmethod
	def tearDown(self):
		print("""\tTest done.""")

	@classmethod
	def tearDownClass(self):
		print("""Channel class test done.""")

	def test_add_interface(self):
		print("""[add_interface]""")
		channel = Link.Channel()

		result = channel.add_interface(1, self.ni1)

		self.assertTrue(result)

	def test_add_interface(self):
		print("""[add_interface] twice""")
		channel = Link.Channel()
		channel.add_interface(1, self.ni1)

		result = channel.add_interface(1, self.ni1)

		self.assertFalse(result)

	def test_add_interface_multiple(self):
		print("""[add_interface] with 2 interfaces""")
		channel = Link.Channel()
		channel = Link.Channel()
		channel.add_interface(1, self.ni1)

		result = channel.add_interface(2, self.ni2)

		self.assertTrue(result)

	def test_add_interface_too_many(self):
		print("""[add_interface] with more than 2 interfaces""")
		channel = Link.Channel()
		channel.add_interface(1, self.ni1)
		channel.add_interface(2, self.ni2)

		result = channel.add_interface(3, Link.NetworkInterface())

		self.assertFalse(result)

	def test_status(self):
		print("""[status]""")
		channel = Link.Channel()

		self.assertTrue(channel.status())

	def test_cutoff(self):
		print("""[status] after cutoff""")
		channel = Link.Channel()

		channel.cutoff()

		self.assertFalse(channel.status())

	def test_recover(self):
		print("""[status] after cutoff and recover""")
		channel = Link.Channel()

		channel.cutoff()

		self.assertFalse(channel.status())

		channel.recover()

		self.assertTrue(channel.status())

	def test_send_to(self):
		print("""[send_to] with simple message""")
		channel = Link.Channel()
		channel.add_interface(1, self.ni1)
		channel.add_interface(2, self.ni2)

		expected = Link.SUCCESS

		message = Link.Message(Link.Message.PING, 1, "test")

		result = channel.send_to(2, message)

		self.assertEqual(result, expected)

	def test_send_to_on_cutoff(self):
		print("""[send_to] with simple message on broken channel""")
		channel = Link.Channel()
		channel.add_interface(1, self.ni1)
		channel.add_interface(2, self.ni2)
		channel.cutoff()

		expected = Link.CUTOFF

		message = Link.Message(Link.Message.PING, 1, "test")

		result = channel.send_to(2, message)

		self.assertEqual(result, expected)

	def test_send_to_incorrect_interface(self):
		print("""[send_to] with incorrect interface""")
		channel = Link.Channel()
		channel.add_interface(1, self.ni1)
		channel.add_interface(2, self.ni2)

		expected = Link.FAILED

		message = Link.Message(Link.Message.PING, 1, "test")

		result = channel.send_to(3, message)

		self.assertEqual(result, expected)


class TestParty(unittest.TestCase):
	@classmethod
	def setUpClass(self):
		print("""Launching Party class test...""")

	@classmethod
	def setUp(self):
		print("""\tLaunching new test:""", end=" ")

	@classmethod
	def tearDown(self):
		print("""\tTest done.""")

	@classmethod
	def tearDownClass(self):
		print("""Party class test done.""")

	def test_get_pid(self):
		print("[get_pid]")
		p = Party.Party(1)
		expected = 1

		result = p.get_pid()

		self.assertEqual(result, expected)

	def test_get_network_interface(self):
		print("[get_network_interface]")
		p = Party.Party(1)

		expected = Link.NetworkInterface

		result = type(p.get_network_interface())

		self.assertEqual(result, expected)

	def test_connect_to(self):
		print("[connect_to]")
		p1 = Party.Party(1)
		p2 = Party.Party(2)

		result = p1.connect_to(p2)

		self.assertTrue(result)

	def test_connect_to_with_channel(self):
		print("[connect_to] with already existing channel")
		p1 = Party.Party(1)
		p2 = Party.Party(2)

		channel = Link.Channel()

		result = p1.connect_to(p2, channel = channel)

		self.assertTrue(result)

	def test_connect_to_bis(self):
		print("[connect_to] on already set")

		p1 = Party.Party(1)
		p2 = Party.Party(2)

		channel1 = Link.Channel()
		channel2 = Link.Channel()

		p1.connect_to(p2, channel = channel1)
		result = p1.connect_to(p2, channel = channel2)

		self.assertFalse(result)

class TestMaster(unittest.TestCase):
	@classmethod
	def setUpClass(self):
		print("""Launching Party class test...""")

	@classmethod
	def setUp(self):
		print("""\tLaunching new test:""", end=" ")

	@classmethod
	def tearDown(self):
		print("""\tTest done.""")

	@classmethod
	def tearDownClass(self):
		print("""Party class test done.""")

	def test_makeCircuit(self):
		print(f"""[makeCircuit]""")
		master = Party.Master(1)
		master.known_parties = [2,3,4]
		master.prime_p = 31
		master.k = 3

		result = master.makeCircuit()

		expected = Crypto.Circuit()
		a = Crypto.Gate(Crypto.Gate.SHARE, value = 2)
		b = Crypto.Gate(Crypto.Gate.SHARE, value = 3)
		c = Crypto.Gate(Crypto.Gate.SHARE, value = 4)

		gate1 = Crypto.Gate(Crypto.Gate.ADD)
		gate1.set_inputs([a,b])
		expected.add_gate(gate1)

		gate2 = Crypto.Gate(Crypto.Gate.ADD)
		gate2.set_inputs([gate1, c])
		expected.add_gate(gate2)

		self.assertEqual(result, expected)

if __name__ == '__main__':
	unittest.main()