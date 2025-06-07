#!/bin/bash/python3
#encoding: utf-8

import random
import threading
import time
from . import Link, Crypto, Frame

class PCEPSException(Exception):
	pass

class Party():
	START = 0
	AWAITING = 1
	SYNC = 2
	COMP = 3
	RES = 4

	def get_str_state(s):
		if s == Party.START:
			return "START"
		if s == Party.AWAITING:
			return "AWAITING"
		if s == Party.SYNC:
			return "SYNC"
		if s == Party.COMP:
			return "COMP"
		if s == Party.RES:
			return "RES"

	def __init__(self, party_id, master = False, version = Frame.Frame.PCEPS):
		self.master = master
		self.isProvider = False
		self.state = Party.START # current state of the party
		self.party_id = party_id # party identifier
		self.networkInterface = Link.NetworkInterface() # link to Network Interface
		self.networkInterface.set_recv_handler(lambda message: self.on_recv(message))
		self.networkInterface.start()
		self.known_parties = [self.party_id] # list of known parties by the party
		self.blacklist = []
		self.shares = {} # set of shares received from every party
		self.B_vectors = {}
		self.circuit = None # circuit to be computed by the parties
		self.applicant = None # id of the party who sent a request
		self.timeout = 10 # timeout in seconds used by the party to not block itself
		self.k = 0 # number of parties that must participate to the computation
		self.prime_p = 0 # prime number used as modulo during computation
		self.prime_g = 0 # prime number used by VSS
		self.results = {}
		self.r_vect = {}
		self.final_result = None
		self.advert_start_count = 0
		self.advert_count_threshold = 3
		self.version = version
		self.stop_prot = False

	def log(self, message):
		with open("/tmp/log.log", "a") as f:
			if self.master:
				text = f"[Master: {self.party_id}] {message}"
			else:
				text = f"[PARTY: {self.party_id}] {message}"
			print(text)
			f.write(text + "\n")

	def clean(self):
		self.state = Party.AWAITING
		self.shares = {} # set of shares received from every party
		self.B_vectors = {}
		self.circuit = None # circuit to be computed by the parties
		self.applicant = None # id of the party who sent a request
		self.k = 0 # number of parties that must participate to the computation
		self.prime_p = 0 # prime number used as modulo during computation
		self.results = {}
		self.r_vect = {}
		self.final_result = None
		self.advert_start_count = 0
		# self.version = Frame.Frame.PCEPS
		self.stop_prot = False

		self.log("cleaning")

	def sanity_check(self):
		"""
		Perform the sanity check of the MPC protocol. It checks if all the parameters are pertinent in order to perform the computation.
		"""
		if self.k < 2:
			return False

		begin = time.time()
		n = len(self.known_parties) # every known party (itself in it)
		while n < self.k:
			if time.time() - begin > self.timeout:
				self.clean()
				return False

			n = len(self.known_parties) # every known party + itself

		if Crypto.isPrime(self.prime_p):
			return True

		return False

	def runPCEPS(self):
		self.log("run PCEPS")
		begin = time.time()

		while self.state == Party.SYNC:
			if time.time() - begin >= self.timeout:
				#never received the SYNC frames => clear data in preparation of new request
				self.clean()
				self.log("Never received the SYNC frames before timeout.")
				return

			continue

		#Phase 1/4: OFFLINE
		if not self.sanity_check():
			self.clean()
			self.log("Sanity Check didn't pass.")
			return 

		self.r_vect = Crypto.compute_recombination_vector(self.known_parties, self.prime_p)

		#Phase 2/4: INPUT SHARING
		if self.isProvider:
			#send shares
			secret = random.randint(15, 25)
			self.log(f"secret = {secret}")
			shares = Crypto.create_shares(secret, self.known_parties, self.k, self.prime_p)
			self.log(f"shares = {shares}")

			for s_id in shares.keys():
				if s_id == self.party_id:
					self.shares[s_id] = shares[s_id]
				else:
					frame = Frame.Frame(Frame.Frame.SHARE, self.version, self.party_id, shares[s_id])
					message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
					self.send(message, s_id)

		begin = time.time()

		#Phase 3/4: COMPUTATION
		#expect shares
		while not all(e in list(self.shares.keys()) for e in self.circuit.get_input_ids()):
			if time.time() - begin >= self.timeout:
				#not enough shares received before timeout => stop computation and clear data in preparation of new request
				self.log(f"{len(self.shares.keys())}, {len(self.known_parties)}")
				self.log("A party failed to participate.")
				self.clean()
				return

			continue

		#we received the shares
		gate = None
		for _ in range(len(self.circuit)):
			gate = self.circuit.get_next_gate()
			self.log(f"computing {gate}")
			for i in gate.get_inputs():
				if i.get_type() == Crypto.Gate.SHARE:
					self.log(f"i.p_id = {i.get_result()}; share = {self.shares}")
					#assign share value to the share input
					i.add_inputs([self.shares[i.get_result()]])
					i.compute()

			gate.compute()
			if gate.get_type() == Crypto.Gate.MUL:
				#behavior is different with MUL gates
				self.log(f"cannot compute MUL gate for now. WIP")

		#Phase 4/4: Result sharing and reconstruction
		#all the gates have been processed
		self.log(f"got a result")
		result = gate.get_result()
		self.results[self.party_id] = result
		if not self.master:
			#we can send the result to the party that sent the request
			frame = Frame.Frame(Frame.Frame.RESULT, self.version, self.party_id, result)
			message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
			self.log(f"sending result {result} to {self.applicant}")
			self.send(message, self.applicant)
			self.state = Party.RES
		else:
			self.log(f"its mine, waiting for the others")
			begin = time.time()
			# wait for results
			while len(self.results) < len(self.known_parties):
				if time.time() - begin > self.timeout:
					self.log(f"{len(self.results)}, {len(self.known_parties)-1}")
					self.clean()
					self.log(f"Parties failed to run the protocol.")
					return

			self.state = Party.RES

			r_number = len(self.results)
			self.log(f"r_vect = {self.r_vect}, results = {self.results}")
			self.final_result = Crypto.compute_MPC_result(self.r_vect, self.results, self.prime_p)/self.k

			self.log(f"result = {self.final_result}")

		self.clean()

	def runPCEAS(self):
		self.log("run PCEAS")
		begin = time.time()

		self.r_vect = Crypto.compute_recombination_vector(self.known_parties, self.prime_p)

		while self.state == Party.SYNC:
			if time.time() - begin >= self.timeout:
				#never received the SYNC frames => clear data in preparation of new request
				self.clean()
				self.log("Never received the SYNC frames before timeout.")
				return

			continue

		#Phase 1/4: OFFLINE
		if not self.sanity_check():
			self.clean()
			self.log("Sanity Check didn't pass.")
			return

		#Phase 2/4: INPUT SHARING
		if self.isProvider:
			#send shares
			secret = random.randint(15, 25)
			self.log(f"secret = {secret}")
			shares, b_vect = Crypto.create_shares(secret, self.known_parties, self.k, self.prime_p, pceas_prime = self.prime_g)
			self.log(f"shares = {shares}")

			frame = Frame.Frame(Frame.Frame.BVECT, self.version, self.party_id, b_vect)
			message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
			self.send(message)

			for s_id in shares.keys():
				if s_id == self.party_id:
					self.shares[s_id] = shares[s_id]
				else:
					frame = Frame.Frame(Frame.Frame.SHARE, self.version, self.party_id, shares[s_id])
					message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
					self.send(message, s_id)

		begin = time.time()

		#Phase 3/4: COMPUTATION
		#expect shares
		while not all(e in list(self.B_vectors.keys()) for e in self.circuit.get_input_ids()) and not self.stop_prot:
			if time.time() - begin >= self.timeout:
				#not enough B vectors received before timeout => stop computation and clear data in preparation of new request
				party_copy = self.known_parties.copy()
				party_copy.remove(self.party_id)
				for party in self.B_vectors.keys():
					party_copy.remove(party)

				if len(party_copy) > 0:
					frame = Frame.Frame(Frame.Frame.MALICIOUS, self.version, self.party_id, party_copy)
					for e in party_copy:
						if e == self.party_id:
							continue
						if e not in self.blacklist:
							self.blacklist.append(e)
							self.log(f"Blacklisted {e}")

						if e in self.known_parties:
							self.known_parties.remove(e)

					message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
					self.send(message)
				self.clean()
				self.log("A party failed to participate.")
				return

			continue

		while not all(e in list(self.shares.keys()) for e in self.circuit.get_input_ids()) and not self.stop_prot:
			if time.time() - begin >= self.timeout:
				#not enough shares received before timeout => stop computation and clear data in preparation of new request
				party_copy = self.known_parties.copy()
				party_copy.remove(self.party_id)
				for party in self.shares.keys():
					party_copy.remove(party)

				if len(party_copy) > 0:
					frame = Frame.Frame(Frame.Frame.MALICIOUS, self.version, self.party_id, party_copy)
					for e in party_copy:
						if e not in self.blacklist:
							self.blacklist.append(e)
							self.log(f"Blacklisted {e}")

						if e in self.known_parties:
							self.known_parties.remove(e)

					message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
					self.send(message)
				self.clean()
				self.log("A party failed to participate.")
				return

			continue

		if self.stop_prot:
			self.clean()
			self.log("Stop the protocol due to VSS")
			return

		#we received the shares
		#check that shares have not been modified
		suspected = []
		for party, share in self.shares.items():
			if not party == self.party_id:
				tot = 0
				for i in range(self.k):
					tot = (tot + self.B_vectors[party][i]*(self.party_id**i))%self.prime_p
				if (share * self.prime_g)%self.prime_p != tot%self.prime_p:
					# there has been a modification somewhere from party. Suspect malicious behavior
					self.log(f"{(share * self.prime_g)%self.prime_p} != {tot}, {self.prime_p}")
					if party not in self.blacklist:
						self.blacklist.append(party)
						self.log(f"Blacklisted {party}")
					if party in self.known_parties:
						self.known_parties.remove(party)
					suspected.append(party)

		if len(suspected) > 0:
			frame = Frame.Frame(Frame.Frame.MALICIOUS, self.version, self.party_id, suspected)
			message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
			self.send(message)

			self.clean()
			self.log("VSS did not pass")
			return

		#compute gates
		gate = None
		for _ in range(len(self.circuit)):
			if self.stop_prot:
				self.clean()
				self.log("Stop the protocol due to VSS")
				return
			gate = self.circuit.get_next_gate()
			self.log(f"computing {gate}")
			for i in gate.get_inputs():
				if i.get_type() == Crypto.Gate.SHARE:
					self.log(f"i.p_id = {i.get_result()}; share = {self.shares}")
					#assign share value to the share input
					i.add_inputs([self.shares[i.get_result()]])
					i.compute()

			gate.compute()
			if gate.get_type() == Crypto.Gate.MUL:
				#behavior is different with MUL gates
				self.log(f"cannot compute MUL gate for now. WIP")

		if self.stop_prot:
			self.clean()
			self.log("Stop the protocol due to VSS")
			return

		#Phase 4/4: Result sharing and reconstruction
		#all the gates have been processed
		self.log(f"got a result")
		result = gate.get_result()
		self.results[self.party_id] = result
		if not self.master:
			#we can send the result to the party that sent the request
			frame = Frame.Frame(Frame.Frame.RESULT, self.version, self.party_id, result)
			message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
			self.log(f"sending result {result} to {self.applicant}")
			self.send(message, self.applicant)
			self.state = Party.RES
		else:
			self.log(f"its mine, waiting for the others")
			begin = time.time()
			# wait for results
			while len(self.results) < len(self.known_parties) and not self.stop_prot:
				if time.time() - begin > self.timeout:
					self.clean()
					self.log(f"Parties failed to run the protocol.")
					return

			if self.stop_prot:
				self.clean()
				self.log("Stop the protocol due to VSS")
				return

			self.state = Party.RES

			r_number = len(self.results)
			self.log(f"r_vect = {self.r_vect}, results = {self.results}")
			self.final_result = Crypto.compute_MPC_result(self.r_vect, self.results, self.prime_p)/self.k

			self.log(f"result = {self.final_result}")

		self.clean()


	def on_recv(self, message):
		"""
		Handler used when a party receives a message.

		Arguments:
			message (Message): the received message
		"""
		m_type, m_origin, m_content = message.get()

		if m_type == Link.Message.FRAME:
			self.log(f"received Message of type {'PING' if m_type == 0 else 'FRAME'} from {m_origin} with payload {m_content} in state {Party.get_str_state(self.state)}")

			if m_origin in self.blacklist:
				self.log(f"rejected because {m_origin} is blacklisted")
				return
			
			if self.state == Party.START:
				if m_content.get_type() == Frame.Frame.ADVERT:
					#expect only to receive other parties joining info
					party = m_content.get_payload()
					if not party in self.known_parties and not party in self.blacklist:
						self.known_parties.append(party)
						self.networkInterface.set_party(party, m_origin)
						self.log(f"{self.known_parties}")
					elif party != self.party_id and not party in self.blacklist:
						self.networkInterface.set_party(party, m_origin)
						self.log(f"{party} updated ({party} != {self.party_id})")
					elif party in self.blacklist:
						self.log(f"{party} is blacklisted.")

			elif self.state == Party.AWAITING:
				if m_content.get_type() == Frame.Frame.ADVERT:
					#expect new parties to enter the network
					party = m_content.get_payload()
					if not party in self.known_parties and not party in self.blacklist:
						self.known_parties.append(party)
						self.networkInterface.set_party(party, m_origin)
						self.log(f"{self.known_parties}")
						# advert the party
						frame = Frame.Frame(Frame.Frame.ADVERT, self.version, self.party_id, self.party_id)
						message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
						self.send(message)
					elif party != self.party_id and not party in self.blacklist:
						self.networkInterface.set_party(party, m_origin)
						self.log(f"{party} updated ({party} != {self.party_id})")
					elif party in self.blacklist:
						self.log(f"{party} is blacklisted.")

				elif m_content.get_type() == Frame.Frame.LEAVE:
					#expect parties to leave the network
					party = m_content.get_payload()
					if party in self.known_parties:
						self.known_parties.remove(party)

				elif m_content.get_type() == Frame.Frame.REQUEST:
					#expect request messages from the master node
					party = m_content.get_payload()
					if party != self.party_id:
						self.version = m_content.get_version()
						self.state = Party.SYNC
						self.log(f"waiting for Sync")
						if self.version == Frame.Frame.PCEPS:
							self.runPCEPS()
						elif self.version == Frame.Frame.PCEAS:
							self.runPCEAS()

			elif self.state == Party.SYNC:
				"""
				if m_content.get_type() == Frame.Frame.ADVERT:
					#expect new parties to enter the network
					party = m_content.get_payload()
					if not party in self.known_parties:
						self.known_parties.append(party)
						self.networkInterface.set_party(party, m_origin)
						self.log(f"{self.known_parties}")
						self.log(f"received advertisement from {party}")
						# advert the party
						frame = Frame.Frame(Frame.Frame.ADVERT, m_content.get_version(), self.party_id, self.party_id)
						message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
						self.send(message)
					elif party != self.party_id:
						self.networkInterface.set_party(party, m_origin)
						self.log(f"{party} updated")
				"""

				if m_content.get_type() == Frame.Frame.LEAVE:
					#expect parties to leave the network
					party = m_content.get_payload()
					if party in self.known_parties:
						self.log(f"{party} left the network")
						self.known_parties.remove(party)

				elif m_content.get_type() == Frame.Frame.SYNC:
					# expect sync messages
					party = m_content.get_origin()
					version = m_content.get_version()
					if version == self.version:
						if version == Frame.Frame.PCEPS:
							self.prime_p, self.circuit = m_content.get_payload()
							self.k = len(self.circuit.get_input_ids())
						elif version == Frame.Frame.PCEAS:
							self.prime_p, self.prime_g, self.circuit = m_content.get_payload()
							self.k = len(self.circuit.get_input_ids())

						if party != self.party_id:
							if self.party_id in self.circuit.get_input_ids():
								self.isProvider = True
							self.log(f"COMPUTE")
							self.state = Party.COMP

					else:
						self.log(f"Received SYNC frame from {party} but versions do not match. Expected {self.version} but received {version}.")

			elif self.state == Party.COMP:
				"""if m_content.get_type() == Frame.Frame.ADVERT:
					#expect new parties to enter the network
					party = m_content.get_payload()
					if not party in self.known_parties:
						self.known_parties.append(party)
						self.networkInterface.set_party(party, m_origin)
						self.log(f"{self.known_parties}")
						# advert the party
						frame = Frame.Frame(Frame.Frame.ADVERT, m_content.get_version(), self.party_id, self.party_id)
						message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
						self.send(message)
					elif party != self.party_id:
						self.networkInterface.set_party(party, m_origin)
						self.log(f"{party} updated")"""

				if m_content.get_type() == Frame.Frame.LEAVE:
					#expect parties to leave the network
					party = m_content.get_payload()
					if party in self.known_parties:
						self.known_parties.remove(party)

				elif m_content.get_type() == Frame.Frame.SHARE:
					#expect share from a party
					share = m_content.get_payload()
					p_id = m_content.get_origin()
					version = m_content.get_version()
					if version == self.version:
						if not p_id in self.shares.keys():
							#only if no share already received from this party
							self.log(f"Received share from {p_id}: {share}")
							self.shares[p_id] = share
							#self.log(f"self.shares = {self.shares}")
					else:
						self.log(f"Received SHARE frame from {p_id} but versions do not match. Expected {self.version} but received {version}.")

				elif m_content.get_type() == Frame.Frame.BVECT:
					if self.version == Frame.Frame.PCEAS:
						vect = m_content.get_payload()
						party = m_content.get_origin()
						if party in self.known_parties and party != self.B_vectors.keys():
							self.log(f"Received B vector from {party}: {vect}")
							self.B_vectors[party] = vect
					else:
						self.log(f"Received BVECT frame but not running PCEAS")

				elif m_content.get_type() == Frame.Frame.MUL:
					# TODO: expect MUL gate results
					pass

				elif m_content.get_type() == Frame.Frame.RESULT:
					# expect Results to be shared
					result = m_content.get_payload()
					p_id = m_content.get_origin()
					version = m_content.get_version()
					if version == self.version:
						self.results[p_id] = result
						self.log(f"Result received from {p_id}: {result}")
						if len(list(self.results.keys())) == len(list(self.known_parties)):
							self.state = Party.RES
					else:
						self.log(f"Received RESULT frame from {p_id} but versions do not match. Expected {self.version} but received {version}.")

				elif m_content.get_type() == Frame.Frame.MALICIOUS:
					# expect Malicious behavior to be suspected
					suspected = m_content.get_payload()
					origin = m_content.get_origin()
					if self.version == Frame.Frame.PCEAS:
						self.stop_prot = True
						#propagate the information in case a packet is lost
						if not all(e in self.blacklist for e in suspected):
							for e in suspected:
								if not e in self.blacklist:
									self.blacklist.append(e)
									self.log(f"Blacklisted {e} by {origin}")
								if e in self.known_parties:
									self.known_parties.remove(e)
							frame = Frame.Frame(Frame.Frame.MALICIOUS, self.version, self.party_id, suspected)
							message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
							self.send(message)


			elif self.state == Party.RES:
				"""if m_content.get_type() == Frame.Frame.ADVERT:
					#expect new parties to enter the network
					party = m_content.get_payload()
					if not party in self.known_parties:
						self.known_parties.append(party)
						self.networkInterface.set_party(party, m_origin)
						self.log(f"{self.known_parties}")
						# advert the party
						frame = Frame.Frame(Frame.Frame.ADVERT, m_content.get_version(), self.party_id, self.party_id)
						message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
						self.send(message)
					elif party != self.party_id:
						self.networkInterface.set_party(party, m_origin)
						self.log(f"{party} updated")"""

				if m_content.get_type() == Frame.Frame.LEAVE:
					#expect parties to leave the network
					party = m_content.get_payload()
					if party in self.known_parties:
						self.known_parties.remove(party)

	def get_pid(self):
		"""
		Get the party pid.

		Returns:
			The pid.
		"""
		return self.party_id

	def get_network_interface(self):
		"""
		Get the party's network interface.

		Returns:
			Network interface of the party.
		"""
		return self.networkInterface

	def send(self, message, to_pid = None):
		"""
		Send messages to the given party.

		Arguments:
			message (Message): the message to send.
			to_pid (int): to id of the party whom the message is destinated to. (Optional, default: None = broadcast)
		"""
		if to_pid:
			self.log(f"sending to {to_pid} {message}")
			self.networkInterface.send_to(to_pid, message)
		else:
			self.log(f"broadcasting {message}")
			self.networkInterface.broadcast(message)

	def leave(self):
		"""
		Quit the running application and advert the network.
		"""
		self.log(f"Leaves the network")
		frame = Frame.Frame(Frame.Frame.LEAVE, self.version, self.party_id, self.party_id)
		message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
		self.send(message)

	def run(self):
		self.log("starts")
		self.log(f"My ip is {self.networkInterface.get_addr()}")

		self.state = Party.AWAITING
		self.log("AWAITING")

		begin = time.time()
		while self.advert_start_count < self.advert_count_threshold:
			if time.time() - begin >= self.timeout:
				frame = Frame.Frame(Frame.Frame.ADVERT, self.version, self.party_id, self.party_id)
				message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
				self.send(message)

				self.advert_start_count += 1
				begin = time.time()

		while True:
			#We could have a verification on battery for IoT or an event on a computer that would break the loop
			continue

		#leave the network
		self.leave()
		self.log(f"FINISH")

class Master(Party):
	def __init__(self, pid, version = Frame.Frame.PCEPS):
		super(Master, self).__init__(pid, master = True, version = version)

	def makeCircuit(self):
		if len(self.known_parties) == self.k:
			picked_parties = self.known_parties
		else:
			parties = self.known_parties.copy()
			parties.remove(self.party_id)
			picked_parties = []
			while len(picked_parties) < self.k:
				p = random.choice(parties)
				parties.remove(p)
				picked_parties.append(p)
		
		input_gates = []
		for party in picked_parties:
			gate = Crypto.Gate(Crypto.Gate.SHARE, value = party)
			gate.set_prime(self.prime_p)
			input_gates.append(gate)

		self.circuit = Crypto.Circuit()

		gate = Crypto.Gate(Crypto.Gate.ADD)
		gate.set_prime(self.prime_p)
		gate.set_inputs(input_gates[0:2])
		self.circuit.add_gate(gate)
		previous_gate = gate

		for i in range(len(input_gates)-2):
			gate = Crypto.Gate(Crypto.Gate.ADD)
			gate.set_prime(self.prime_p)
			gate.set_inputs([previous_gate, input_gates[2+i]])
			self.circuit.add_gate(gate)
			previous_gate = gate

		return self.circuit


	def run(self):
		self.log("starts")
		self.log(f"My ip is {self.networkInterface.get_addr()}")

		self.state = Party.AWAITING

		while True:
			time.sleep(30) # send every 10 min (wait 5min before + 5min after)

			#P2: set parameters
			self.log("Setting parameters")
			z = Crypto.generateRandomPrime(2**31//2, 2**32//2-1) #unsigned int
			self.prime_p = z
			begin = time.time()
			n = len(self.known_parties) # every known party (itself in it)
			self.log(f"{self.known_parties}, {n}")
			ok = True
			while n < 3:
				if time.time() - begin > self.timeout:
					print(self.known_parties)
					self.clean()
					self.log(f"Not enough parties connected to run the protocol.")
					ok=False
					break

				n = len(self.known_parties) # every known party

			if ok:
				tmax = round(n/2)-1
				if tmax <= 2:
					threshold = 2
				else:
					#randomize the threshold needed for this computation
					threshold = random.randint(2, tmax)
				self.log(f"Parameters: (n = {n}, t = {threshold}, z = {z})")

				#P3: prepare the circuit
				self.log(f"Building up the circuit")
				self.k = threshold
				self.makeCircuit()

				#P4: Request
				self.log(f"Sending the Request")
				frame = Frame.Frame(Frame.Frame.REQUEST, self.version, self.party_id, self.party_id)
				message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
				self.send(message)
				self.state = Party.SYNC

				#P5: SYNC
				self.log(f"Sync all the participants")
				if self.version == Frame.Frame.PCEAS:
					self.prime_g = Crypto.generateRandomPrime(2**31//2, 2**32//2-1)
					payload = (self.prime_p, self.prime_g, self.circuit)
				else:
					payload = (self.prime_p, self.circuit)
				frame = Frame.Frame(Frame.Frame.SYNC, self.version, self.party_id, payload)
				message = Link.Message(Link.Message.FRAME, self.networkInterface.get_addr(), frame)
				self.send(message)

				self.state = Party.COMP
				self.log("COMPUTE")

				#P6: compute the circuit
				if self.version == Frame.Frame.PCEPS:
					self.runPCEPS()
				elif self.version == Frame.Frame.PCEAS:
					self.runPCEAS()

			time.sleep(30)

		self.leave()
		self.log("FINISH")