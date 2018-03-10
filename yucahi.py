import threading
import time
import crayons
import sys
from scapy.all import *
from manuf import manuf
import datetime
from math import log10
import json

verbose=0
intfmon=sys.argv[1]

class Scanner(object):
	def __init__(self, intfmon):
		self.intfmon = intfmon
		self.iw_ch = 1
		self.ap_dict = {}
		self.client_dict = {}
		self.stored_ssids = []
		self._macparser = None
		self._hop_interval = 4

	def prepare_mac_parser(self):
		print("\033[H\033[J")
		print(crayons.white("|>>>> Loading vendors from oui.."))
		self._macparser = manuf.MacParser(update=True)

	def prepare_device(self):
		print(crayons.white("|>>>> Setting up device..."))
		print('---> Bringing interface DOWN')
		os.system('sudo ifconfig %s down' %(self.intfmon))
		print('---> Unblocking RFKill')
		os.system('sudo rfkill unblock wifi; sudo rfkill unblock all')
		print('---> Setting monitor mode')
		os.system('sudo iwconfig %s mode monitor' %(self.intfmon))
		print('---> Bringing interface UP')
		os.system('sudo ifconfig %s up' %(self.intfmon))
		time.sleep(3)

	def hop_channels(self):
		while True:
			os.system('sudo iwconfig %s channel %i' %(self.intfmon, self.iw_ch))
			time.sleep(self._hop_interval)
			if self.iw_ch == 14:
				self.iw_ch = 1
			else:
				self.iw_ch = self.iw_ch + 1

	def calculate_distance(self, channel, signal):
		# Channels and frequencies are as follows:
		# 1 	2412
		# 2 	2417
		# 3 	2422
		# 4 	2427
		# 5 	2432
		# 6 	2437
		# 7 	2442
		# 8 	2447
		# 9 	2452
		# 10 	2457
		# 11 	2462
		# 12 	2467
		# 13 	2472
		# 14 	2484
		freq = [
		2412,
		2417,
		2422,
		2427,
		2432,
		2437,
		2442,
		2447,
		2452,
		2457,
		2462,
		2467,
		2472,
		2484
		]
		try:
			MHz=int(freq[int(channel) + 1])
			dBm=int(signal)

			FSPL = 27.55
			# Free-Space Path Loss adapted avarage constant for home WiFI routers and following units

			m = 10 ** (( FSPL - (20 * log10(MHz)) + dBm ) / 20 )
			return round(m,2)
		except:
			return '??.??'

	def packet_handler(self, pkt) :
		if pkt.haslayer(Dot11) :
			if pkt.type == 0 and pkt.subtype == 8:     		## beacon frame
				if pkt.addr3 not in self.ap_dict:
					if pkt.info == "":
						ssid = "<hidden>"
					else:
						ssid = pkt.info
					self.ap_dict[pkt.addr2] = {
						'ssid': ssid,
						'last_seen_at': str(datetime.datetime.now())
					}
					self.generate_and_write_json(self.ap_dict, 'ap')

	       		elif pkt.type == 0 and pkt.subtype == 4:    ## probe request
					if pkt.info != '':                  	## broadcast probe request
						p = pkt[Dot11Elt]
						cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
					                      "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
						ssid, channel = None, None
						crypto = set()
						while isinstance(p, Dot11Elt):
							if p.ID == 0:
								ssid = p.info
							elif p.ID == 3:
								channel = ord(p.info)
							elif p.ID == 48:
								crypto.add("WPA2")
							elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
								crypto.add("WPA")
							p = p.payload

						if not crypto:
							if 'privacy' in cap:
								crypto.add("WEP")
							else:
								crypto.add("OPN")

						# If mac address is already included
						if pkt.addr2 in self.client_dict.keys():
							self.stored_ssids = self.client_dict[pkt.addr2]['ssids']
							# If current SSID is not in list
							if pkt.info not in self.client_dict[pkt.addr2]['ssids']:
								self.stored_ssids.append(pkt.info)
							self.client_dict[pkt.addr2] = {
								'last_seen_at': time.time(),
								'signal': self.dbm(pkt),
								'ch': channel,
								'dist': self.calculate_distance(channel, self.dbm(pkt)), 'ssids': self.stored_ssids}
						else:
							self.client_dict[pkt.addr2] = {
								'last_seen_at': time.time(),
								'signal': self.dbm(pkt),
								'ch': channel,
								'dist': self.calculate_distance(channel, self.dbm(pkt)), 'ssids': [pkt.info]}
					self.generate_and_write_json(self.client_dict, 'clients')

	def dbm(self, pkt):
		try:
			nd = pkt[RadioTap].notdecoded
			return 256-ord(nd[-4:-3])
		except:
			return 100

	def print_all(self):
		while True:
			print("\033[H\033[J")
			# self.print_ap()
			self.print_cli()
			time.sleep(2)

	def generate_and_write_json(self, dictionary, name):
		json_string = json.dumps(dictionary)
		with open('./%s.json' %(name), 'w') as f:
			f.write(json_string)

	def print_ap(self):
		print(crayons.white("|>>>> Beacons in channel [%s] (%s)..." %(self.iw_ch, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")), bold=True))
		print('')
		ap_dict_sorted = sorted(self.ap_dict.items(), key=lambda ap_dict: (ap_dict[1]['last_seen_at']), reverse = True)
		for ap, data in ap_dict_sorted: # Copy dict so it doesn't fail when iterating and thread changes dict data
			print(crayons.green("[%s] \t(%s, %s) \t\t%s" %(
			ap,
			self._macparser.get_manuf(ap),
			self._macparser.get_comment(ap),
			str(data['ssid'])
			)))
		print('')

	def print_cli(self):
		print(crayons.white("|>>>> Probe Requests in channel [%s] (%s)..." %(self.iw_ch, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")), bold=True))
		print('')
		client_dict_sorted = sorted(self.client_dict.items(), key=lambda client_dict: (client_dict[1]['last_seen_at']), reverse = True)
		for cli, data in client_dict_sorted:
			elapsed_diff = time.time() - data['last_seen_at']
			elapsed = time.strftime("%H:%M:%S", time.gmtime(elapsed_diff))
			if elapsed_diff <= 10.0:
				print(crayons.green("%s ago \t[%s] \t-%sdBm \t{%sm} \t%s (%s)" %(
				elapsed,
				str(data['ch']),
				str(data['signal']),
				str(data['dist']),
				cli,
				self._macparser.get_manuf(cli)
				)))
				for ssid in data['ssids']:
					print(crayons.green("  -----> %s" %(ssid)))

			elif elapsed_diff > 10 and elapsed_diff < 60:
				print(crayons.yellow("%s ago \t[%s] \t-%sdBm \t{%sm} \t%s (%s)" %(
				elapsed,
				str(data['ch']),
				str(data['signal']),
				str(data['dist']),
				cli,
				self._macparser.get_manuf(cli)
				)))
				for ssid in data['ssids']:
					print(crayons.yellow("  -----> %s" %(ssid)))
			else:
				print(crayons.red("%s ago \t[%s] \t-%sdBm \t{%sm} \t%s (%s)" %(
				elapsed,
				str(data['ch']),
				str(data['signal']),
				str(data['dist']),
				cli,
				self._macparser.get_manuf(cli)
				)))
				for ssid in data['ssids']:
					print(crayons.red("  -----> %s" %(ssid)))
		print('')

	def sniff_it(self):
		sniff(iface=intfmon, prn = self.packet_handler)

scanner = Scanner(intfmon)
# time.sleep(3)
scanner.prepare_mac_parser()
scanner.prepare_device()

sniff_thread = threading.Thread(target=scanner.sniff_it, args=())
sniff_thread.daemon = True
sniff_thread.start()

channel_hopper = threading.Thread(target=scanner.hop_channels, args=())
channel_hopper.daemon = True
channel_hopper.start()

# PrintAP()
scanner.print_all()
