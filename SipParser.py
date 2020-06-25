#!/usr/bin/python -u
# -*- coding: utf-8 -*-
import bisect
import dpkt
import re
import sys
from datetime import datetime
from socket import inet_ntoa
from scapy.all import rdpcap, sniff
from scapy.layers.inet import TCP, UDP, IP, ICMP
from random import randint

class SIPMessage:
	def __init__(self, body="", header="", sdp=""):
		self.Diversion = []
		self.PAI = []
		self.PPI = []
		self.RPID = []
		self.From = ""
		self.To = ""
		self.Contact = ""
		self.UA = ""
		self.CallID = ""
		self.srcnum = ""
		self.dstnum = ""
		self.method = ""
		self.srcip = ""
		self.dstip = ""
		self.srcport = ""
		self.dstport = ""
		self.body = ""
		self.header = ""
		self.timestamp = ""
		self.sdp = sdp
		self.setBody(body)
		self.setHeader(header)

	def __cmp__(self, other):
		return cmp(self.timestamp, other.timestamp)

	def __eq__(self, other):
		return self.timestamp == other.timestamp and self.header == other.header and self.body == other.body

	def extractNumFromUri(self, uri):
		"""Extract number from URI and return it.
			 URI should look like <sip:123456@x.x.x.x> at this point
			 with optional ;variable=value suffixes"""
		num = ""
		try:
			if "<tel:" in uri:
				# Fix for UA's that send incorrectly formatted tel: headers
				# (example: <tel:1819@10.18.19.101>
				if "@" in uri:
					start, stop = (uri.find(":")+1, uri.find("@"))
				else:
					start, stop = (uri.find(":")+1, uri.find(">"))
			else:
				start, stop = (uri.find(":")+1, uri.find("@"))
			num = uri[start:stop]
		except:
			pass

		# Get rid of E.164 (+) formatting
		num = num.replace("+", "00")
		return num


	def setHeader(self, header):
		#13:14:41.595803 IP 172.25.200.121.5080 > 172.25.200.101.5060: SIP, length: 743
		self.header = header
		fields = header.split(" ")
		try:
			self.timestamp = datetime.strptime(fields[0], "%H:%M:%S.%f").time()
		except:
			pass
		try:
			srcinfo = fields[2]
			sep_loc = srcinfo.rindex(".")
			self.srcip = srcinfo[0:sep_loc] 
			self.srcport = srcinfo[sep_loc+1:]

			dstinfo = fields[4]
			sep_loc = dstinfo.rindex(".")
			self.dstip = dstinfo[0:sep_loc]
			self.dstport = dstinfo[sep_loc+1:-1]
		except Exception, e:
			pass

	def setBody(self, body):
		def getContent(line):
			return line[line.index(":")+2:].lstrip().rstrip()

		def getTelnum(line):
			begin = "sip:"
			end = "@"
			try:
				startloc = line.index(begin)+len(begin)
				stoploc = line.index(end)
				return line[startloc:stoploc]
			except:
				return ""

		def getMethod(line):
			if line.startswith("SIP"):
				return line[line.index(" ")+1:]
			else:
				return line[:line.index(" ")]

		self.body = body
		self.Diversion = []
		self.From = ""
		self.To = ""
		self.Contact = ""

		n = 0
		for line in self.body.splitlines():
			n += 1
			if n == 1:
				self.method = getMethod(line)
				continue

			l = line.lower()
			if "diversion" in l:
				self.Diversion.append(getContent(line))
			elif "p-asserted-identity" in l:
				self.PAI.append(getContent(line))
			elif "p-preferred-identity" in l:
				self.PPI.append(getContent(line))
			elif "remote-party-id" in l:
				self.RPID.append(getContent(line))
			elif l.startswith("from:"):
				self.From = getContent(line)
				self.srcnum = getTelnum(self.From)
			elif l.startswith("to:"):
				self.To = getContent(line)
				self.dstnum = getTelnum(self.To)
			elif l.startswith("user-agent:"):
			 	self.UA = getContent(line)
			elif l.startswith("call-id"):
				self.CallID = getContent(line)

	def hasSdp(self):
		return self.sdp != ""

	def hasHeader(self):
		return self.header != ""

	def hasDiversion(self):
		return len(self.Diversion) > 0

	def hasPAI(self):
		return len(self.PAI) > 0

	def hasPPI(self):
		return len(self.PPI) > 0

	def hasRPID(self):
		return len(self.RPID) > 0

	def hasPrivacy(self):
		for headers in (self.PAI, self.PPI, self.RPID):
			for header in headers:
				if "privacy" in header.lower():
					if "privacy=off" not in header.lower():
						return True

		return False

	def __repr__(self):
		return "'%s %s'" % (self.timestamp, self.method)

	def __str__(self):
		message = "%s%s%s" % (self.header, self.body, self.sdp)
		# Split lines and join them to get rid of trailing empty lines
		return "\n".join(message.splitlines())

class SIPConversation:
	"""A conversation of SIP messages, stored as a list sorted by timestamp of reception"""
	def __init__(self):
		self.messages = []
		# Meta-information about the first SIP message received in the conversation
		self.srcnum = ""
		self.From = ""
		self.dstnum = ""
		self.To = ""
		self.srcip = ""
		self.dstip = ""
		self.timestamp = ""
		self.method = ""
		self.CallID = ""

	def add(self, message):
		assert isinstance(message, SIPMessage)
		if message not in self.messages:
			bisect.insort(self.messages, message)

		# Update information as we might have received packets out of order
		self.srcnum = self.messages[0].srcnum
		self.From = self.messages[0].From
		self.dstnum = self.messages[0].dstnum
		self.To = self.messages[0].To
		self.method = self.messages[0].method
		self.srcip = self.messages[0].srcip
		self.dstip = self.messages[0].dstip
		self.timestamp = self.messages[0].timestamp
		self.CallID = self.messages[0].CallID

	def __iter__(self):
		return iter(self.messages)

	def __str__(self):
		retval = ""
		t = "%-4s %-20s %-45s (%s->%s)\n"
		for i in enumerate(self.messages):
			msgno = "[%s]" % (i[0])
			message = i[1]
			retval += t % (msgno, message.timestamp, message.method, message.srcnum or message.From, message.dstnum or message.To)
		return retval.rstrip()

	def __repr__(self):
		f = self.srcnum or self.From
		t = self.dstnum or self.To
		ts = str(self.timestamp)
		return "'%s: %s %s->%s'" % (ts, self.method, f, t)

	def __cmp__(self, other):
		# This relies on messages being sorted at all times
		return cmp(self.messages[0].timestamp, other.messages[0].timestamp)

	def __hash__(self):
		return hash(self.messages[0].CallID)

	def __eq__(self, other):
		return self.messages[0].CallID == other.messages[0].CallID

	def __getitem__(self, item):
		return self.messages[item]

	def dump(self):
		for message in self.messages:
			print message.method

	def getDiversion(self):
		for message in self.messages:
			if message.method == "INVITE":
				return message.Diversion

	def _isNumInOverlord(self, telnum, headers):
		for message in self.messages:
			if message.method == "INVITE":
				for header in eval(headers):
					num = message.extractNumFromUri(header)
					if telnum == num:
						return True
		return False

	def isNumInDiversion(self, telnum):
		return self._isNumInOverlord(telnum, "message.Diversion")

	def isNumInPAI(self, telnum):
		return self._isNumInOverlord(telnum, "message.PAI")

	def isNumInPPI(self, telnum):
		return self._isNumInOverlord(telnum, "message.PPI")

	def isNumInRPID(self, telnum):
		return self._isNumInOverlord(telnum, "message.RPID")

	def getTimestamp(self):
		return self.messages[0].timestamp

	def showInitialSummary(self):
		"""Show nice brief, initial summary of the first method recorded"""
		f = self.srcnum or self.From
		t = self.dstnum or self.To
		ts = str(self.timestamp)
		return "%s: %s %s->%s" % (ts, self.method, f, t)

	def _hasOverlord(self, func):
		for message in self.messages:
			if message.method == "INVITE":
				return eval(func)

	def hasDiversion(self):
		return self._hasOverlord("message.hasDiversion()")

	def hasPAI(self):
		return self._hasOverlord("message.hasPAI()")

	def hasPPI(self):
		return self._hasOverlord("message.hasPPI()")

	def hasRPID(self):
		return self._hasOverlord("message.hasRPID()")

	def hasPrivacy(self):
		return self._hasOverlord("message.hasPrivacy()")

class SIPConversations:
	def __init__(self):
		self.conversations = {}

	def add(self, conversation):
		if not conversation.CallID in self.conversations:
			self.conversations[conversation.CallID] = conversation

	def clear(self):
		self.conversations = {}

	def addMessage(self, message):
		"""Add message to conversation. If conversations does not exits; create it"""
		try:
			self.conversations[message.CallID].add(message)
		except KeyError:
			self.conversations[message.CallID] = SIPConversation()
			self.conversations[message.CallID].add(message)

	def getBySrcnum(self, telnum):
		"""Given a telnum (str), this will return conversations
		whose initiator is telnum"""
		assert isinstance(telnum, str) == True
		filtered = SIPConversations()
		for k, v in self.conversations.iteritems():
			if v.srcnum == telnum:
				for m in v:
					filtered.addMessage(m)
		return filtered

	def getByDstnum(self, telnum):
		"""Given a telnum (str), this will return conversations
		whose receiver is telnum"""
		assert isinstance(telnum, str) == True
		filtered = SIPConversations()
		for k, v in self.conversations.iteritems():
			if v.dstnum == telnum:
				for m in v:
					filtered.addMessage(m)
		return filtered

	def getByTelnum(self, telnum):
		"""Given a telnum (str), this will return conversations
		whose initiator or receiver is telnum"""
		assert isinstance(telnum, str) == True
		filtered = SIPConversations()
		for k, v in self.conversations.iteritems():
			if v.srcnum == telnum or v.dstnum == telnum:
				for m in v:
					filtered.addMessage(m)
		return filtered

	def getByDiversion(self, telnum=None):
		"""Given a telnum (str), this will return conversations
		whose diverter is telnum (or if header is present, if
		telnum is None"""
		assert isinstance(telnum, str) == True or telnum is None
		filtered = SIPConversations()
		for k, v in self.conversations.iteritems():
			if v.hasDiversion():
				if telnum is None or v.isNumInDiversion(telnum):
					for m in v:
						filtered.addMessage(m)
		return filtered

	def getByPAI(self, telnum=None):
		"""Given a telnum (str), this will return conversations
		whose P-Asserted-Identity is telnum (or if header is present,
		if telnum is None"""
		assert isinstance(telnum, str) == True or telnum is None
		filtered = SIPConversations()
		for k, v in self.conversations.iteritems():
			if v.hasPAI():
				if telnum is None or v.isNumInPAI(telnum):
					for m in v:
						filtered.addMessage(m)
		return filtered

	def getByPPI(self, telnum=None):
		"""Given a telnum (str), this will return conversations
		whose P-Preffered-Identity is telnum (or if header is present, 
		if telnum is None)"""
		assert isinstance(telnum, str) == True or telnum is None
		filtered = SIPConversations()
		for k, v in self.conversations.iteritems():
			if v.hasPPI():
				if telnum is None or v.isNumInPPI(telnum):
					for m in v:
						filtered.addMessage(m)
		return filtered

	def getByRPID(self, telnum=None):
		"""Given a telnum (str), this will return conversations
		whose P-Preffered-Identity is telnum (or if header is present, 
		if telnum is None)"""
		assert isinstance(telnum, str) == True or telnum is None
		filtered = SIPConversations()
		for k, v in self.conversations.iteritems():
			if v.hasRPID():
				if telnum is None or v.isNumInRPID(telnum):
					for m in v:
						filtered.addMessage(m)
		return filtered

	def getByPrivacy(self):
		"""Returns conversations where privacy is present in headers"""
		filtered = SIPConversations()
		for k, v in self.conversations.iteritems():
			if v.hasPrivacy():
				for m in v:
					filtered.addMessage(m)
		return filtered


	def getBySrcIp(self, ip):
		"""Given an IP address, this will return conversations
		whose initiator is ip"""
		assert isinstance(ip, str) == True
		filtered = SIPConversations()
		for k, v in self.conversations.iteritems():
			if v.srcip == ip:
				for m in v:
					filtered.add(m)
		return filtered

	def getByDstIp(self, ip):
		"""Given an IP address, this will return conversations
		whose receiver is ip"""
		assert isinstance(ip, str) == True
		filtered = SIPConversations()
		for k, v in self.conversations.iteritems():
			if v.dstip == ip:
				for m in v:
					filtered.add(m)
		return filtered

	def getByIp(self, ip):
		"""Given an IP address, this will return conversations
		whose initiator or receiver is ip"""
		assert isinstance(ip, str) == True
		filtered = SIPConversations()
		for k, v in self.conversations.iteritems():
			if v.srcip == ip or v.dstip == ip:
				for m in v:
					filtered.add(m)
		return filtered

	def sorted(self):
		return self.sortedByTimestamp()

	def sortedByTimestamp(self):
		return [self.conversations[x] for x in sorted(self.conversations.keys(), key=lambda c: self.conversations[c].timestamp)]

	def getByIndex(self, i):
		return self.sortedByTimestamp()[i]

	def getByCallId(self, callid):
		return self.conversations[callid]

	def has_key(self, callid):
		return self.conversations.has_key(callid)

	def iteritems(self):
		return self.conversations.iteritems()

	def keys(self):
		return self.conversations.keys()

	def values(self):
		return self.conversations.values()

	def items(self):
		return self.conversations.items()

	def pop(self, k, d=None):
		return self.conversations.pop(k, d)

	def pop(self, *args):
		return self.conversations.pop(*args)

	def update(self, *args, **kwargs):
		return self.conversations.update(*args, **kwargs)

	def __iter__(self):
		return iter(self.conversations)

	def __getitem__(self, callid):
		return self.conversations[callid]

	def __setitem__(self, callid, conversation):
		assert isinstance(conversation, SIPConversation)
		self.conversations[callid] = conversation

	def __delitem__(self, callid):
		del self.conversations[callid]

	def __contains__(self, item):
		return item in self.conversations

	def __copy__(self):
		return self.conversations.copy()

	def __len__(self):
		return len(self.conversations)

	def __repr__(self):
		return repr(self.conversations)

class ParseError(ValueError):
	pass

def read_sip_messages_pcap(fh):
	HDR_TEMPLATE = "%s IP %s.%s > %s.%s: SIP, length: %s\n"

	print "Processing file %s..." % (fh.name)
	packets = rdpcap(fh.name)
	print "Processed packets: %s" % (repr(packets)[len(fh.name)+3:-1])
	for packet in packets:
		if not (packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP))):
			continue

		ip = packet.payload
		transport = ip.payload
		application = transport.payload
		app_list = str(application).splitlines()
		try:
			if not "SIP/2.0" in app_list[0]:
				continue
		except IndexError:
			# No application layer. Skip.
			continue

		dt = datetime.fromtimestamp(packet.time).strftime("%H:%M:%S.%f")
		srcip = ip.src
		dstip = ip.dst
		srcport = transport.sport
		dstport = transport.dport
		header = HDR_TEMPLATE % (dt, srcip, srcport, dstip, dstport, len(application))
		try:
			sdp_start_idx= app_list.index("")+1
			body = "\r\n".join(app_list[:sdp_start_idx-1])
			sdp = "\r\n".join(app_list[sdp_start_idx:])
			if sdp:
				sdp += "\r\n\r\n"
		except IndexError:
			body = "\r\n".join(app_list)

		body += "\r\n\r\n"
		yield SIPMessage(body, header, sdp)

def read_sip_messages_dpkt_pcap(fh):
	HDR_TEMPLATE = "%s IP %s.%s > %s.%s: SIP, length: %s\n"
	i = 0
	for ts, buf in dpkt.pcap.Reader(fh):
		try:
			i += 1
			print "processing pkt", i
			# First assume linux cooked mode encapsulation (when using tcpdump "any" interface)
			eth = dpkt.sll.SLL(buf)
			try:
				ip = eth.ip
			except AttributeError:
				# Then try normal Ethernet encapsulation
				eth = dpkt.ethernet.Ethernet(buf)
				try:
					ip = eth.ip
				except AttributeError:
					# Both have failed. Skip over this packet.
					continue

			transport = ip.data
			if not (isinstance(transport, dpkt.udp.UDP) or isinstance(transport, dpkt.tcp.TCP)):
				continue
			application = transport.data

			dt = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")
			srcip = inet_ntoa(ip.src)
			dstip = inet_ntoa(ip.dst)
			srcport = transport.sport
			dstport = transport.dport
			if not application:
				continue

			if "SIP" in application.splitlines()[0]:
				header = HDR_TEMPLATE % (dt, srcip, srcport, dstip, dstport, len(application))
				appdata = application.split("\r\n\r\n")
				appdata_wrong_newline = application.split("\n\n")

				# Check if message had only \n for newlines, instead of specced \r\n
				if len(appdata_wrong_newline) > len(appdata):
					appdata = appdata_wrong_newline

				message = appdata[0]
				try:
					sdp = appdata[1]
				except IndexError:
					sdp = ""

				# Put back the original newlines that we used to split
				message += "\r\n\r\n"
				sdp += "\r\n"

				yield SIPMessage(message, header, sdp)

		except dpkt.dpkt.NeedData:
			pass

def read_sip_messages_txt(fh):
	sip_methods = ("INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "PRACK", "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER", "MESSAGE", "UPDATE")
	in_message = False
	has_sdp = False
	header = ""
	message = ""
	sdp = ""
	in_sdp = False

	print "Processing file %s..." % (fh.name)
	while True:
		try:
			line = next(fh)
			if not in_message:
				if re.match(r'^\d\d:\d\d:\d\d\.\d{6}', line) and "SIP" in line:
					in_message = True
					header = line

					# Let's process next line(s) here too, as we need to clean up some garbage
					# in front of the SIP method from tcpdump. Might be multiple lines due to 
					# possibility of garbage containing newline characters
					found_method = False
					while found_method == False:
						line = next(fh)
						lline = line.lower()
						if re.match(r'^\d\d:\d\d:\d\d\.\d{6}', line):
							if "sip" in lline:
								# We found new header. Last message was empty
								header = line
								continue
							else:
								# New header for non-SIP message found. Won't try to find header
								in_message = False
								break

						# Sanitize method line as we usually have some garbage
						# Note that for unsupported methods we still might get some garbage.
						sip_request = r'(\w+)\s+sip:.*sip\/2\.0$'
						sip_response = r'sip\/2.0\s+(\w+\s\w+).*$'
						match = re.search(sip_request, lline.rstrip()) or re.search(sip_response, lline.rstrip())
						if match:
							line = line[match.start():]
							lline = lline[match.start():]

							# We don't need to further sanitize responses as we know the exact starting position already.
							# Further, we can have all sorts of cutesy stuff like 100 trying -- your call is important to us
							if not lline.startswith("sip/2.0"):
								for method in sip_methods:
									method = method.lower()
									if lline.startswith(method):
										# We already have a sanitized match, line starts with method
										break
									else:
										# We have a method, but we have to sanitize some garbage
										loc = lline.find(method)
										if loc != -1:
											line = line[loc:]
											break
							message += line
							found_method = True
							break
					continue
				else:
					continue

			if in_sdp:
				sdp += line
			else:
				message += line
				
			if "content-length" in line.lower():
				content_length = int(line.split(":")[1].rstrip().lstrip())
				if content_length != 0:
					has_sdp = True
				continue

			# Check if we're at end of SIP part
			if len(line.rstrip().lstrip()) == 0:
			 	if has_sdp == True:
			 		in_sdp = True
			 		# We've already passed one empty line, so let's just say we don't have it
			 		# as that should put us in the correct state
			 		has_sdp = False
				else:
					yield SIPMessage(message, header, sdp)
					header = ""
					message = ""
					sdp = ""
					in_message = False
					in_sdp = False
	
		except StopIteration:
			if in_message:
				raise ParseError("Unexpected end of message")
			else:
				raise StopIteration


def read_sip_messages(fh):
	if fh.name.endswith(".pcap"):
		return read_sip_messages_pcap(fh)
	else:
		return read_sip_messages_txt(fh)

def sniff_sip_messages(stopper, iface=None):
	packets = []
	def process_pkt(pkt):
		packets.append(pkt)
	def should_stop(pkt):
		if stopper.isSet():
			return True
		else:
			return False

	HDR_TEMPLATE = "%s IP %s.%s > %s.%s: SIP, length: %s\n"
	counter = 0
	if iface:
		sniff(iface, prn=process_pkt, store=1, stop_filter=should_stop)
	else:
		sniff(prn=process_pkt, store=1, stop_filter=should_stop)

	for packet in packets:
		if not (packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP))):
			continue

		ip = packet.payload
		transport = ip.payload
		application = transport.payload
		app_list = str(application).splitlines()
		try:
			if not "SIP/2.0" in app_list[0]:
				continue
		except IndexError:
			# No application layer. Skip.
			continue

		dt = datetime.fromtimestamp(packet.time).strftime("%H:%M:%S.%f")
		srcip = ip.src
		dstip = ip.dst
		srcport = transport.sport
		dstport = transport.dport
		header = HDR_TEMPLATE % (dt, srcip, srcport, dstip, dstport, len(application))
		try:
			sdp_start_idx= app_list.index("")+1
			body = "\r\n".join(app_list[:sdp_start_idx-1])
			sdp = "\r\n".join(app_list[sdp_start_idx:])
			if sdp:
				sdp += "\r\n\r\n"
		except IndexError:
			body = "\r\n".join(app_list)

		body += "\r\n\r\n"
		yield SIPMessage(body, header, sdp)
	
if __name__ == "__main__":
	f = open(sys.argv[1])

	conversations = SIPConversations()
	for message in read_sip_messages(f):
		conversations.addMessage(message)

	for conversation in conversations.sorted():
	#	print conversation
		for message in conversation:
			print message.method, ":",
		print ""

	print "=" * 20

	for conversation in conversations.getBySrcnum("4341147").sorted():
		print conversation

	print "=" * 20

	print "Diversions..."
	for k, v in conversations.getByDiversion("1819").iteritems():
		for m in v:
			if m.method == "INVITE":
				print m
#				for divheader in m.Diversion:
#					print m.num_from_uri(divheader)
#			
#			if m.method == "INVITE": print m
#	for callid, value in conversations.getBySrcnum("4341147").iteritems():
#		print "%s: %s %s %s" % (callid, value.timestamp, value.method, value.srcip)

#	for conversation in conversations.getByIp("178.19.48.132").sorted():
#		print "%s->%s" % (conversation.srcip, conversation.dstip)
