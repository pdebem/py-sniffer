#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from sniffer import Sniffer


sniffer = Sniffer("wlan0") # FIXME: parametrizar interface
try:
	sniffer.start()
	user = raw_input("Aperte enter para parar o Sniffer...")
except:
	print("\n === + Erro ao executar o sniffer: {} + ===".format(sys.exc_info()[0]))
finally:
	sniffer.exit()
