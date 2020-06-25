#!/usr/bin/python
# -*- coding: utf-8 -*-
from SipInvestigator import MainCLI
import sys

if __name__ == '__main__':
	if len(sys.argv) > 1:
		MainCLI(sys.argv[1]).cmdloop()
	else:
		MainCLI().cmdloop()
