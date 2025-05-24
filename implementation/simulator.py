#!/bin/bash/python3
#encoding: utf-8

from core import Party, Frame
import sys
import os

if __name__ == '__main__':
	id = os.getenv('PARTY_ID') # ou paramètrer manuellement
	with open("/tmp/log.log", "a") as f:
		print(sys.byteorder)
		f.write(sys.byteorder + "\n")

	master = False
	if "-master" in sys.argv:
		master = True
	
	if master:
		party = Party.Master(int(1), version = Frame.Frame.PCEAS)
	else:
		party = Party.Party(int(id))

	party.run()
