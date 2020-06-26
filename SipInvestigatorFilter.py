#!/usr/bin/python -u
# -*- coding: utf-8 -*-
import sys
import cmd
from SipParser import SIPConversations

class FilterCLI(cmd.Cmd):
	"""Filter configurion sub CLI"""
	FILTER_ARGUMENTS = ("srcnum", "dstnum", "telnum", "ip", "srcip", "dstip", "diversion", "pai", "ppi", "has")
	FILTER_HAS_ARGUMENTS = ("diversion", "privacy", "pai", "ppi", "rpid")
	SET_ARGUMENTS = {"condition": ["and", "or"]}

	def __init__(self, parent):
		cmd.Cmd.__init__(self)
		self.parent = parent
		self._prompt = ("SipInv[filter]", ": ")
		self._update_prompts()

	def apply_filter(self):
		parent = self.parent
		flt = parent.filter
		convs = parent.conversations
		convs_flt = parent.conversations_filtered
		convs_flt.clear()

		if not self.parent.filter:
			parent.conversations_filtered_sorted = []
			print "%s conversations" % (len(convs))
			return True

		# Default condition is or
		condition = "or"

		if "condition" in flt:
			condition = flt['condition']
			if condition == "and":
				convs = SIPConversations()
				for conv in parent.conversations:
					convs.add(parent.conversations[conv])

		for arg in self.FILTER_ARGUMENTS:
			if arg in flt:
				if arg == "has":
					for subarg in flt[arg]:
						if subarg == "diversion":
							func = convs.getByDiversion
						elif subarg == "pai":
							func = convs.getByPAI
						elif subarg == "ppi":
							func = convs.getByPPI
						elif subarg == "rpid":
							func = convs.getByRPID
						elif subarg == "privacy":
							func = convs.getByPrivacy

						for k in func():
							convs_flt.add(convs[k])
				else:
					if arg == "srcnum":
						func = convs.getBySrcnum
					elif arg == "dstnum":
						func = convs.getByDstnum
					elif arg == "telnum":
						func = convs.getByTelnum
					elif arg == "srcip":
						func = convs.getBySrcIp
					elif arg == "dstip":
						func = convs.getByDstIp
					elif arg == "ip":
						func = convs.getByIp
					elif arg == "diversion":
						func = convs.getByDiversion
					elif arg == "pai":
						func = convs.getByPAI

					for identifier in flt[arg]:
						for k in func(identifier):
							convs_flt.add(convs[k])

				if condition == "and":
					convs = SIPConversations()
					for conv in convs_flt:
						convs.add(convs_flt[conv])
					convs_flt = SIPConversations()
		if condition == "and":
			convs_flt = convs
			parent.conversations_filtered = convs_flt
		parent.conversations_filtered_sorted = convs_flt.sorted()
		print "%s conversations" % (len(convs_flt))
		return True

	def _update_prompts(self):
		if len(self.parent.filter) != 0:
			self.prompt = "%s*%s" % (self._prompt)
			self.parent.prompt = "%s*%s" % (self.parent._prompt)
		else:
			self.prompt = "%s%s" % (self._prompt)
			self.parent.prompt = "%s%s" % (self.parent._prompt)

	def do_add(self, args):
		"""Add a filter condition"""
		if len(args) == 0:
			self.parent.printErr("Missing argument(s)")
			return False
		def try_add(ftype, fvalue):
			if ftype == "has" and value not in self.FILTER_HAS_ARGUMENTS:
				self.parent.printErr("Could not add '%s': Invalid filter argument" % (fvalue))
				return False
			elif ftype not in self.FILTER_ARGUMENTS:
				self.parent.printErr("Could not add '%s': Invalid filter" % (ftype))
				return False

			try:
				if value not in self.parent.filter[ftype]:
					self.parent.filter[ftype].append(fvalue)
				else:
					self.parent.printErr("Could not add '%s': Item already in filter" % (fvalue))
					return False
			except KeyError:
				self.parent.filter[ftype] = [fvalue]

			self.apply_filter()
			return True

		args = args.split()
		ftype = args[0]
		values = args[1:]

		if len(values) == 0:
			self.parent.printErr("Could not add '%s': Filter expects arguments" % (ftype))

		for value in values:
			try_add(ftype, value)

		self._update_prompts()

	def help_add(self):
		print "\nAdd a filter to select a subset of conversations matching filter. Valid arguments are:\n"
		self.parent.printHelpLine("", "Select conversations where...")
		self.parent.printHelpLine("diversion", "<telnum> [telnum(s)]", "<telnum> is in one of the Diversion headers")
		self.parent.printHelpLine("dstip", "<ip> [ip(s)]", "<ip> is the destination address")
		self.parent.printHelpLine("dstnum", "<telnum> [telnum(s)]", "<telnum> is the destination number")
		self.parent.printHelpLine("has", "<header>", "<header> is present. Use 'help add has' for details")
		self.parent.printHelpLine("ip", "<ip> [ip(s)]", "<ip> is either the source or destination ip address")
		self.parent.printHelpLine("pai", "<telnum>", "<pai> is in one of the P-Asserted-Identity headers")
		self.parent.printHelpLine("ppi", "<telnum>", "<ppi> is in one of the P-Preferred-Identity headers")
		self.parent.printHelpLine("srcip", "<ip> [ip(s)]", "<ip> is the destionation address")
		self.parent.printHelpLine("srcnum", "<telnum> [telnum(s)]", "<telnum> is the source number")
		self.parent.printHelpLine("telnum", "<telnum> [telnum(s)]", "<telnum> is either the source or destionation number")

		print "\nExamples:"
		examples = []
		examples.append("""%sadd srcnum 4151500
5 conversations""" % (self.parent.prompt))
		examples.append("""%sadd srcnum 4151500 4151502
7 conversations""" % (self.parent.prompt))
		examples.append("""%sadd has diversion
87 conversations""" % (self.parent.prompt))
		for example in examples:
			for line in example.splitlines():
				self.parent.printHelpLine(line)
			print ""

	def do_set(self, args):
		"""Set a filter condition"""
		if len(args) == 0:
			self.parent.printErr("Missing argument(s)")
			return False
		args = args.split()
		ftype = args[0]
		values = " ".join(args[1:])

		if ftype not in self.SET_ARGUMENTS:
			self.parent.printErr("Invalid argument: %s" % (ftype))
			return False
		if values not in self.SET_ARGUMENTS[ftype]:
			self.parent.printErr("Invalid value for argument '%s': %s" % (ftype, values))
			return False

		self.parent.filter[ftype] = values
		self.apply_filter()
		self._update_prompts()

	def complete_set(self, text, line, begidx, endidx):
		if line.startswith("set condition"):
			return [x for x in self.SET_ARGUMENTS['condition'] if x.startswith(text) or text == "condition"]

		return [x for x in self.SET_ARGUMENTS if x.startswith(text) and begidx == 4]

	def do_del(self, args):
		"""Remove a filter condition"""
		args = args.split()
		if not args:
			self.parent.printErr("Missing argument(s)")
			return False
		ftype = args[0]
		values = args[1:]

		try:
			if len(values) == 0:
				del self.parent.filter[ftype]
			else:
				for value in values:
					try:
						self.parent.filter[ftype].remove(value)
					except ValueError:
						self.parent.printErr("Unable to remove %s: No such item" % (value))
				if len(self.parent.filter[ftype]) == 0:
					del self.parent.filter[ftype]
		except KeyError:
			self.parent.printErr("No such filter: '%s'" % ftype)

		self.apply_filter()
		self._update_prompts()

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
					self.parent.printHelpLine(name, "", getattr(self, "do_" + name).__doc__ or "")
			print ""

	def complete_add(self, text, line, begidx, endidx):
		__PARAMS_EXPECTING_TELNUM = ("srcnum", "dstnum", "telnum", "diversion" ,"pai", "ppi")

		def telnum_completion():
			l = ""
			if text != "":
				l += " "
			if line.rstrip().endswith(__PARAMS_EXPECTING_TELNUM):
				l += "<telnum>\n"
			else:
				l += "[telnum]\n"
			l += "%s%s" % (self.prompt, line)
			return l

		if line.startswith(tuple(["add %s" % x for x in __PARAMS_EXPECTING_TELNUM])):
			# Need to use sys.stdout instead of print b/c of print's annoying whitespaces
			sys.stdout.write(telnum_completion())

		elif line.startswith("add has"):
			if text == "has":
				return self.FILTER_HAS_ARGUMENTS
			return [x for x in self.FILTER_HAS_ARGUMENTS if x.startswith(text) and begidx == 8]

		else:
			return [x for x in self.FILTER_ARGUMENTS if x.startswith(text) and begidx == 4]

	def complete_del(self, text, line, begidx, endidx):
		return self.parent.filter

	def do_reset(self, args):
		"""Remove all filter conditions"""
		self.parent.filter = {}
		self.apply_filter()
		self._update_prompts()

	def do_show(self, args):
		print self.parent.filter

	def do_exit(self, line):
		"""Exit filter configuration"""
		return True

	def do_EOF(self, line):
		print ""
		return True


