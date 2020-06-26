#!/usr/bin/python
# -*- coding: utf-8 -*-
import cmd
import os
import SipParser
from glob import glob
from Queue import Queue, Empty
from SipInvestigatorFilter import FilterCLI
from threading import Thread, Event

class MainCLI(cmd.Cmd):
	"""CLI to investigate SIP correspondence"""
	SHOW_ARGUMENTS = ["conversation", "conversations", "filter"]
	SHOW_CONVERSATION_SUBARGUMENTS = ["message", "messages"]
	SHOW_CONVERSATIONS_SUBARGUMENTS = ["sorted"]

	def __init__(self, data=""):
		cmd.Cmd.__init__(self)
		self._prompt = ("SipInv", ": ")
		self.prompt = "".join(self._prompt)
		self.filter = {}
		self.conversations = SipParser.SIPConversations()
		self.conversations_sorted = []
		self.conversations_filtered = SipParser.SIPConversations()
		self.conversations_filtered_sorted = []
		self.capture_queue = None
		self.capture_stopper = None
		self.capture_thread = None

		if data != "":
			self.do_load(data)

	def printErr(self, message):
		print "*** Error! %s" % (message)

	def printHelpLine(self, *args):
		if len(args) == 3:
			print "%-18s %-47s %s" % (args[0], args[1], args[2])
		elif len(args) == 2:
			print "%-18s %-47s %s" % ("", args[0], args[1])
		else:
			print "%-18s %s" % ("", args[0])

	def do_help(self, arg):
		"""List available commands with 'help' or detailed help with 'help <topic>'."""
		if arg:
			funcarg = arg.replace(" ", "_")
			try:
				func = getattr(self, 'help_' + funcarg)
			except AttributeError:
				try:
					doc=getattr(self, 'do_' + funcarg).__doc__
					if doc:
							self.stdout.write("%s\n"%str(doc))
							return
				except AttributeError:
					pass
				self.stdout.write("%s\n"%str(self.nohelp % (arg,)))
				return
			func()
		else:
			print "\nAvailable commands (type help <topic> for help on topic):\n"
			names = self.get_names()
			for name in sorted(names):
				if name[:3] == "do_":
					name = name[3:]
					if name == "EOF":
						continue
					self.printHelpLine(name, "", getattr(self, "do_" + name).__doc__ or "")
			print ""

	def complete_help(self, text, line, begidx, endidx):
		args = line.split()
		names = self.get_names()
		commands = []
		for name in sorted(names):
			if name[:3] == "do_":
				name = name[3:]
				if name == "EOF":
					continue
				commands.append(name)

		if len(args) > 1:
			if args[1] == "show":
				if len(args) >= 3 and line.endswith(" "):
					return 
				else:
					return [x for x in self.SHOW_ARGUMENTS if x.startswith(text)]
			return [command for command in commands if command.startswith(text)]
		else:	
			return [command for command in commands if command.startswith(text)]

	def do_clear(self, line):
		"""Clear the SIP conversation data"""
		self.conversations = SipParser.SIPConversations()

	def do_load(self, filename):
		"""Load SIP data from file."""
		num_conversations_before = len(self.conversations)
		num_messages_before = sum(len(v.messages) for k, v in self.conversations.iteritems())

		if not (filename.endswith(".pcap") or filename.endswith(".txt")):
			self.printErr("Could not open file: Unsupported filetype")
			return False

		try:
			with open(filename, "r") as f:
				for message in SipParser.read_sip_messages(f):
					self.conversations.addMessage(message)
		except IOError as e:
			self.printErr("Could not open file: %s" % (e))

		num_conversations_after = len(self.conversations)
		num_messages_after = sum(len(v.messages) for k, v in self.conversations.iteritems())
		num_conversations = num_conversations_after - num_conversations_before
		num_messages = num_messages_after - num_messages_before
		self.conversations_sorted = self.conversations.sorted()
		print "%s conversations (%s SIP messages) extracted" % (num_conversations, num_messages)

	def do_capture(self, args):
		try:
			arg = args.split()[0]
		except IndexError:
			self.printErr("Missing argument. Valid arguments: start | stop")
			return
		if arg == "start":
			print "Starting packet capture"
			def capper(stopper, queue):
				for message in SipParser.sniff_sip_messages(stopper, queue):
					queue.put(message)

                        self.capture_queue = Queue()
                        self.capture_stopper = Event()
			self.capture_thread = Thread(target=capper, args=(self.capture_stopper, self.capture_queue,))
			self.capture_thread.daemon = True
			self.capture_thread.start()
		elif arg == "stop":
			# TODO maybe update all the counters and data on the fly?
			print "Stopping packet capture"
			self.capture_stopper.set()
			self.capture_thread.join()
			num_conversations_before = len(self.conversations)
			num_messages_before = sum(len(v.messages) for k, v in self.conversations.iteritems())

			while not self.capture_queue.empty():
				message = self.capture_queue.get()
				self.conversations.addMessage(message)

			num_conversations_after = len(self.conversations)
			num_messages_after = sum(len(v.messages) for k, v in self.conversations.iteritems())
			num_conversations = num_conversations_after - num_conversations_before
			num_messages = num_messages_after - num_messages_before
			self.conversations_sorted = self.conversations.sorted()
			print "%s conversations (%s SIP messages) extracted" % (num_conversations, num_messages)

			if self.filter:
				print "Applying filter %s... Result: " % (self.filter),
				flt = FilterCLI(self)
				flt._apply_filter()

	def help_load(self):
		print "Load SIP data from file. Accepted filetypes are .txt and .pcap"

	def complete_load(self, text, line, begidx, endidx):
		def append_slash_if_dir(p):
			if p and os.path.isdir(p) and p[-1] != os.sep:
				return p + os.sep
			else:
				return p

		# Find location of arguments separator
		before_arg = line.rfind(" ", 0, begidx)
		if before_arg == -1:
			return
		else:
			beg_arg = before_arg + 1

		arg = line[beg_arg:endidx]
		globpattern = arg + '*'

		completions = []
		for path in glob(globpattern):
			bn = os.path.basename(path)
			if os.path.isdir(path) and not path.endswith(os.sep):
				completions.append(bn + os.sep)
			else:
				if bn.endswith(".txt") or bn.endswith(".pcap"):
					completions.append(bn)

		return completions

	def do_exit(self, line):
		"""Exit the program"""
		return True
    
	def do_show(self, args):
		"""Show information about configuration and data"""
		args = args.split()
		if not args:
			self.printErr("Missing argument(s)")
			return
		if args[0] not in self.SHOW_ARGUMENTS:
			self.printErr("Invalid argument: '%s'" % (args[0]))
			return

		def show_filter():
			print self.filter

		def show_conversation():
			if len(args) < 2:
				self.printErr("Missing conversation identifier")
				return False

			try:
				conv_id = int(args[1])
			except ValueError:
				conv_id = args[1]

			convs = self.conversations_filtered or self.conversations
			convs_sorted = self.conversations_filtered_sorted or self.conversations_sorted

			conversation = None
			try:
				conversation = convs_sorted[int(conv_id)]
			except ValueError:
				try:
					conversation = convs.getByCallId(conv_id)
				except:
					self.printErr("Conversation '%s' not found" % (conv_id))
					return False
			except (IndexError, KeyError):
				self.printErr("Conversation '%s' not found" % (conv_id))
				return False

			if len(args) > 2:
				if args[2] == "message":
					if len(args) < 4:
						self.printErr("Missing message identifier")
						return False
					try:
						print conversation[int(args[3])]
					except IndexError:
						self.printErr("Message %s not found" % (args[3]))
				if args[2] == "messages":
					for i in enumerate(conversation):
						(msgno, message) = i
						print "=======  Message #%s  =======" % (msgno)
						print message
			else:
				if isinstance(conv_id, int):
					print "===  Conversation Call-ID: %s  ===" % (conversation.CallID)
				print conversation

		def show_conversations():
			if len(self.conversations) == 0:
				print "No conversations loaded. Load conversations with 'load'"
				return
			convs = self.conversations_filtered or self.conversations
			convs_sorted = self.conversations_filtered_sorted or self.conversations_sorted
			if len(args) > 1:
				if args[1] == "sorted":
					for i in enumerate(convs_sorted):
						convno = "[%i]" % (i[0])
						conversation = i[1]
						print "%-5s %s" % (convno, conversation.showInitialSummary())
				else:
					self.printErr("Invalid argument: '%s'" % (args[1]))
			else:
				for k, v in convs.iteritems():
					print "%s: %s" % (k, v.showInitialSummary())

		if args[0] == "filter":
			show_filter()

		if args[0] == "conversation":
			show_conversation()

		if args[0] == "conversations":
			show_conversations()
			
	def complete_show(self, text, line, begidx, endidx):
		# TODO find human readable way of doing below
		args = line.split()
		if len(args) == 1 or (len(args) == 2 and text not in self.SHOW_ARGUMENTS and not line.endswith(" ")):
			# We have 'show', 'show ' or 'show [some text]
			return [x for x in self.SHOW_ARGUMENTS if x.startswith(text)]

		if len(args) > 1:
			if args[1] == "conversation":
				convs = self.conversations_filtered or self.conversations
				convs_sorted = self.conversations_filtered_sorted or self.conversations_sorted
				if len(args) > 2:
					conv_id = args[2]
					if len(args) == 3 and not line.endswith(" "):
						# We have 'show conversation [some text]'
						return [x for x in convs if x.startswith(text)]
					elif (len(args) == 3 and line.endswith(" ")) or (len(args) == 4 and not line.endswith(" ")):
						# We have 'show conversation [some text] ' or 'show conversation [some text] [some other text]'
						return [x for x in self.SHOW_CONVERSATION_SUBARGUMENTS if x.startswith(text)]
					elif args[3] == "message" and len(args) == 4 and line.endswith(" "):
						# We have 'show conversation [some text] message '
						# Return indexes of the messages of a conversation along with message header
						try:
							conv = convs_sorted[int(conv_id)]
						except ValueError:
							conv = convs.getByCallId(conv_id)
						return ["%s:%s" % (i, j.method) for i,j in enumerate(conv)]

				elif line.endswith(" "):
					return [x for x in convs]

				else:
					return [x for x in self.SHOW_ARGUMENTS if x.startswith(text)]

			elif args[1] == "conversations" and (len(args) == 2 or (len(args) == 3 and not line.endswith(" "))):
				# We have 'show conversations ' or 'show conversations [some text]'
				return [x for x in self.SHOW_CONVERSATIONS_SUBARGUMENTS if x.startswith(text)]

	def help_show(self):
		print "Show configuration or data. Type help <topic> for further information."
		print "Valid parameters are:\n"
		self.printHelpLine("conversation", "<call-id|index> [message <index>|messages]",
			"Shows conversation details")
		self.printHelpLine("conversations", "[sorted]",
			"Shows list of conversations, optionally sorted by order received")
		self.printHelpLine("filter", "", "Shows the active conversation filter")

	def help_show_conversation(self):
		print "\nShow conversation details. Valid parameters are:\n"
		self.printHelpLine("show conversation", "<call-id|index> [message <index>|messages]", "Shows conversation details")
		self.printHelpLine("<call-id>", "Shows conversation summary fetched via call-id")
		self.printHelpLine("<index>", "Shows conversation summary fetched via index")
		self.printHelpLine("<call-id|index> [message <index>]", "Shows SIP message <index> of conversation <call-id|index>")
		self.printHelpLine("<call-id|index> [messages]", "Shows all SIP messages of conversation <call-id|index>")
		print "\nExamples:"
		examples = []
		examples.append("""%sshow conversation 1a94-dea-4262017131425-img01.muli-0-172.25.2.22
[0]  13:14:25.024731      INVITE                                        (9991234->1819)
...
[4]  13:14:28.251244      ACK                                           (9991234->1819)""" % (self.prompt))

		examples.append("""%sshow conversation 30
===  Conversation Call-ID: 1a94-dea-4262017131425-img01.muli-0-172.25.2.22  ===
[0]  13:14:25.024731      INVITE                                        (9991234->1819)
...""" % (self.prompt))

		examples.append("""%sshow conversation 30 message 0
13:14:25.024731 IP 172.25.200.101.5060 > 172.25.200.121.5080: SIP, length: 1068
INVITE sip:1819@172.25.200.121:5080 SIP/2.0
...""" % (self.prompt))

		examples.append("""%sshow conversation 30 messages
=======  Message #0  =======
13:14:25.024731 IP 172.25.200.101.5060 > 172.25.200.121.5080: SIP, length: 1068
INVITE sip:1819@172.25.200.121:5080 SIP/2.0
...
...
=======  Message #4  =======
13:14:28.251244 IP 172.25.200.101.5060 > 172.25.200.121.5080: SIP, length: 477
ACK sip:1819@172.25.200.121:5080 SIP/2.0
...""" % (self.prompt))

		for example in examples:
			for line in example.splitlines():
				self.printHelpLine(line)
			print ""

	def help_show_conversations(self):
		print "\nShow all conversations loaded that match the optional filter.\n"
		self.printHelpLine("show conversations", "[sorted]", "Show conversations, optionally sorted")
		print "\nExamples:"
		examples = []
		examples.append("""%sshow conversations
b3682a0-bcb7-1235-e9bd-00215e2dbf92: 13:14:17.605100: 183 Session Progress 9991234->9994321
0e95d5ed-bcb8-1235-e9bd-00215e2dbf92: 13:14:14.622693: INVITE 9994444->4445555
...""" % (self.prompt))
		examples.append("""%sshow conversations sorted
[0]   13:14:08.473270: OPTIONS asterisk-><sip:178.19.48.132>
...
[41]  13:14:33.438543: INVITE 9991337->8001880""" % (self.prompt))
		for example in examples:
			for line in example.splitlines():
				self.printHelpLine(line)
			print ""

	def do_filter(self, args):
		"""Enter SIP filter configuration for filtering conversations"""
		args = args.split()
		i = FilterCLI(self)
		i.cmdloop()

	def do_EOF(self, line):
		print ""
		return True


