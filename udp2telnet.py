#!/usr/bin/env python3

import logging
import socket 
import threading
import datetime,time
import re
from miniboa import TelnetServer, colorize
import WSJTXClass

IDLE_TIMEOUT = 300
CLIENT_LIST = []
SERVER_RUN = True
DecoderArray = {}

def on_connect(client):
	"""
	Sample on_connect function.
	Handles new connections.
	"""
	logging.info("Opened connection to {}".format(client.addrport()))
	#broadcast("{} joins the conversation.\n".format(client.addrport()))
	CLIENT_LIST.append(client)
	client.send("Welcome to the Spot Server, {}.\n".format(client.addrport()))
#	login(client)
	
def login(client) :
	logging.debug("Get callsign from {}".format(client.addrport()))
	CallSign_reg = r'([A-Z]{1,2}|[0-9][A-Z])([0-9])([A-Z]{1,3})'
	while True :
		client.send("Please tell me your Callsign :")
		telnet_server.poll()
		msg = client.get_command()
		if msg is not None :
			logging.debug("Callsign : {}".format(msg))
			try:
				if re.match(CallSign_reg, msg , re.I).span()[0] == 0 :
					logging.info("{} logon the server".format(msg))
					client.callsign = msg
					break
				else:
					logging.debug("Callsign wrong : {}".format(msg))
			except :
				logging.debug("Callsign error : {}".format(msg))

def on_disconnect(client):
	"""
	Sample on_disconnect function.
	Handles lost connections.
	"""
	logging.info("Lost connection to {}".format(client.addrport()))
	CLIENT_LIST.remove(client)
	#broadcast("{} leaves the conversation.\n".format(client.addrport()))
	client.send("73 de bd7nwr ft8 deocder server.")

def process_clients():
	"""
	Check each client, if client.cmd_ready == True then there is a line of
	input available via client.get_command().
	"""
	for client in CLIENT_LIST:
		if client.active and client.cmd_ready:
			# If the client sends input echo it to the chat room
			chat(client)

def chat(client):
	"""
	Echo whatever client types to everyone.
	"""
	global SERVER_RUN
	msg = client.get_command()
	if msg is not None :
		msg = msg.strip().upper()
		logging.info("{} says '{}'".format(client.addrport(), msg))
		if len(msg.split())>0 :
			command = msg.split()[0]
			if command == "HELP" or msg.split()[0] == "?":
				client.send("sa=ba7ib : filter only msg from station ba7ib\n")
				client.send("fe=14074000 : filter only frequency is 14074000\n")
				client.send("ca=y : filter only callsign begin with y\n")
				client.send("mo=ft8 : filter only mode is ft8\n")
				client.send("cq : only cq call will display\n")
				client.send("ck : check your filter\n")
				client.send("nf : clear all filter\n")
				client.send("stations : list all register report station\n")
				client.send("clients : list all listen clients\n")
				client.send("bye : disconnect\n")
			elif msg.split("=")[0] in ['SA', 'FE', 'CA', "MO", "CQ"] :
				client.filter = msg.replace(" ", "")
				client.send(" your filter is : {}\n".format( client.filter ))
			elif command == "NF" :
				client.filter = ""
				client.send("No filters\n")
			elif command == "CK" :
				client.send("{} filter is : {}\n".format( client.callsign,  client.filter ))
			elif msg.split()[0] == 'BYE':			# bye = disconnect
				client.active = False
			elif command == "THREAD" : # check threading status
				client.send("udp for jdtx server(t1) thread is  : " + str(t1.isAlive()) + '\n')
				client.send("spot server thread(t2) is  : " + str(t2.isAlive()) + '\n')
				client.send("udp for raspberry server thread(t3) is  : " + str(t3.isAlive()) + '\n')
			elif command == 'SHUTDONW':			# shutdown == stop the server
				SERVER_RUN = False
			elif command == 'RESTART' :			# restart == restart thread
				client.send("wait 60s for {}\n".format(msg))
				SERVER_RUN = msg.split()
			elif command == 'CLIENTS' :			# clients == list all clients
				for guest in CLIENT_LIST :
					client.send("{} from {} filter {}\n".format(guest.callsign, guest.addrport(), guest.filter))
			elif command == 'STATIONS' :			# stations == list all report stations
				for station in DecoderArray :
					client.send("{} : {}\n".format(station, DecoderArray[station]))
			else :
				client.send("unknow command, try 'help' for all command\n")
	"""
	for guest in CLIENT_LIST:
		if guest != client:
			#guest.send("{} says '{}'\n".format(client.addrport(), msg))
			client.active = True
		else:
			guest.send("You say '{}'\n".format(msg))
	"""

def kick_idle():
	"""
	Looks for idle clients and disconnects them by setting active to False.
	"""
	# Who hasn't been typing?
	for client in CLIENT_LIST:
		if client.idle() > IDLE_TIMEOUT:
			logging.info("Kicking idle lobby client from {}".format(client.addrport()))
			client.active = False

def broadcast(msg):
	"""
	Send msg to every client.
	"""
	for client in CLIENT_LIST:
		if client.callsign != "" or 1:
			msg_color = "^w"
			if msg.split()[5] == "CQ" :
				msg_color = "^G"
				grid = msg.split()[-2]
				if len(grid) == 4 :
					DIS = int(pow((pow(abs(ord(grid[:1])- ord("O")),2) + pow(abs(ord(grid[1:2])-ord("L")),2)),0.5))
					if DIS > 7 :
						msg_color = "^R" 
					elif DIS > 3 and DIS <= 7 :
						msg_color = "^Y"
			msg = colorize( msg_color + msg)
			if len(client.filter) >0 :
				filter = client.filter.split("=")
				if filter[0] == "SA" :
					if msg.split()[-1].split("-")[2] == filter[1] :
						client.send(msg)
				elif filter[0] == "FE" :
					if msg.split()[-1].split("-")[0] == filter[1] :
						client.send(msg)
				elif filter[0] == "CQ" :
					if msg.split()[5] == "CQ" :
						client.send(msg)
				elif filter[0] == "CA" :
					for m in msg.split()[5:-1] :
						if m.find(filter[1]) > 0 :
							client.send(msg)
							break
				elif filter[0] == "MO" :
					if msg.split()[-1].split("-")[1] == filter[1] :
						client.send(msg)
			else :
				client.send(msg)

#No used function for this time
def adif_spot(adif_text):
	adif_data = {}
	resutl = ""
	#https://github.com/ctjacobs/pyqso/blob/master/pyqso/adif.py
	#https://n1mmwp.hamdocs.com/appendices/external-udp-broadcasts/
	p1 = re.compile("(\<parameters\:[0-9]*\>)")
	adif_text = re.sub(p1, "", adif_text)
	p2 = re.compile("<(.*?):(\d*).*?>([^<]+)")
	for item in p2.findall(adif_text) :
		adif_data[item[0]]=item[2][:int(item[1])]
	try:
		Spot = adif_data['STATION_CALLSIGN'].upper() + ":" + "        "
		Freq = "         " + str(float(adif_data['Freq'])*1000) + " "
		Call = adif_data['Call'].upper() + "          "
		Note = adif_data['NOTES'] + "                          "
		Time = adif_data['TIME_ON'][:4] + "Z     "
		Mode = adif_data['Mode'].upper() + "     "
		result = 'DX de ' + Spot[:10] + Freq[:-9] + Call[:10] + Note[:31] + Time[:6] + Mode[:5]
	except :
		result = ""
		print("adif data error %s" % adif_data)
	return result

def receive_udp_2() :
	try:
		mSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		mSocket.bind(("",5556)) 
	except Exception as e:
		logging.error("bind 5556 error {}".format(e))
	else :
		logging.debug("Listening for Plante UDP log on port {}. CTRL-C to break.".format("5556"))
		while True:
			fileContent, (remoteHost, remotePort) = mSocket.recvfrom(1024)
			DecoderStation = ("{}:{}".format(remoteHost, remotePort))
			if DecoderStation not in DecoderArray :
				DecoderArray.update({DecoderStation : ""} )
			msg = fileContent.decode('utf-8')
			if msg[:11] == "<parameters" :
				msg = adif_spot(msg)
			if msg[:12] == "Start Decode" :
				if DecoderArray[DecoderStation] != msg.replace("Start Decode ", "") :
					DecoderArray[DecoderStation] = msg.replace("Start Decode ", "")
					for station in list(DecoderArray.keys()) :
						if DecoderArray[station] == msg.replace("Start Decode ", "") :
							if station != DecoderStation :
								del DecoderArray[station]
			elif msg[:10] == "End Decode" :
				continue
			else :
				broadcast(msg[:51] + DecoderArray[DecoderStation] + '\n')
		
def receive_udp():
	try:
		mSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		mSocket.bind(("",5555)) 
	except Exception as e:
		logging.error("bind 5555 error {}".format(e))
	logging.debug("Listening for WSTJ-X UDP log on port {}. CTRL-C to break.".format("5555"))
	while True:
		fileContent, (remoteHost, remotePort) = mSocket.recvfrom(1024)
		DecoderStation = ("{}:{}".format(remoteHost, remotePort))
#		logging.info("{} send UDP '{}'".format(remoteHost, fileContent))
		NewPacket = WSJTXClass.WSJTX_Packet(fileContent, 0)
		NewPacket.Decode()

		if NewPacket.PacketType == 0:
			HeartbeatPacket = WSJTXClass.WSJTX_Heartbeat(fileContent, NewPacket.index)
			HeartbeatPacket.Decode()
			dataDecode = ("{} {} {}".format(HeartbeatPacket.MaximumSchema, HeartbeatPacket.Version ,HeartbeatPacket.Revision))
			try:
				logging.debug("Heartbeat : {} @ {}".format(dataDecode, DecoderArray[DecoderStation]))
			except :
				logging.debug("Heartbeat : {} @ ".format(dataDecode))

		elif NewPacket.PacketType == 1:
			StatusPacket = WSJTXClass.WSJTX_Status(fileContent, NewPacket.index)
			StatusPacket.Decode()
			dataDecode = ("{:08}-{}-{}".format(StatusPacket.Frequency, StatusPacket.Mode, StatusPacket.DECall))
			#StatusPacket.Decoding
			if DecoderStation not in DecoderArray :
				DecoderArray.update({DecoderStation : ""} )
			if StatusPacket.Decoding and DecoderArray[DecoderStation] != dataDecode:
				DecoderArray[DecoderStation] = dataDecode
				for station in list(DecoderArray.keys()) :
					if DecoderArray[station] == dataDecode :
						if station != DecoderStation :
							del DecoderArray[station]
			logging.debug("Status : {} {} @ {}".format(dataDecode, StatusPacket.Decoding, DecoderArray[DecoderStation]))
#			broadcast("Status : {} {} @ {}\n".format(dataDecode, StatusPacket.Decoding, DecoderArray[DecoderStation]))

		elif NewPacket.PacketType == 2:
			DecodePacket = WSJTXClass.WSJTX_Decode(fileContent, NewPacket.index)
			DecodePacket.Decode()
			# can use PyQt4.QtCore.QTime for this as well!
			s = int(  (DecodePacket.Time/1000) % 60 )
			m = int( ((DecodePacket.Time/(1000*60) ) %60 ) )
			h = int( ((DecodePacket.Time/(1000*60*60)) %24))
			pkmsg = (DecodePacket.Message + '                          ')[:26]
			dataDecode = ("{:02}:{:02}:{:02} {:>3} {:4.1f} {:>4} {} {}".format(h,m,s,DecodePacket.snr,DecodePacket.DeltaTime,DecodePacket.DeltaFrequency,DecodePacket.Mode,pkmsg))
			try :
				logging.debug("Decode : {} @ {}".format(dataDecode, DecoderArray[DecoderStation]))
			except :
				logging.info("Decode : {} @".format(dataDecode))
#			self.DecodeCount += 1
			# now we need to send it to the UI
			try:
				msg = dataDecode + DecoderArray[DecoderStation] + '\n'
			except :
				msg = dataDecode + '@ ' + DecoderStation + '\n'
			broadcast(msg)

		elif NewPacket.PacketType == 3:
			logging.debug("PacketType = 3")

		elif NewPacket.PacketType == 5:
			LoggedPacket = WSJTXClass.WSJTX_Logged(fileContent, NewPacket.index)
			LoggedPacket.Decode()
			logging.debug("LoggedPacket : {}".format(LoggedPacket))
		
def spot_server():
	# Create a telnet server with a port, address,
	# a function to call with new connections
	# and one to call with lost connections.
	telnet_server = TelnetServer(
		port=7300,
		address='',
		on_connect=on_connect,
		on_disconnect=on_disconnect,
		timeout = .05
		)
	logging.debug("Listening for SPOT connections on port {}. CTRL-C to break.".format(telnet_server.port))
	while SERVER_RUN:
		telnet_server.poll()
#		kick_idle() 
		process_clients()
	
if __name__ == '__main__':

	# Simple chat server to demonstrate connection handling via the
	# async and telnet modules.

	logging.basicConfig(level=logging.INFO,#控制台打印的日志级别
		filename='/tmp/udp2telnet.log',
		filemode='w',##模式，有w和a，w就是写模式，每次都会重新写日志，覆盖之前的日志
		#a是追加模式，默认如果不写的话，就是追加模式
		format='%(asctime)s - [line:%(lineno)d] - %(levelname)s: %(message)s'    #日志格式
	)

	t1 = threading.Thread(target=receive_udp, name='receive_udp_server')
	t2 = threading.Thread(target=spot_server, name='telnet_server')
	t3 = threading.Thread(target=receive_udp_2, name='receive_udp_server_2')
	# Server Loop
	while SERVER_RUN:
		if not t2.isAlive() :
			logging.info("Start telnet_server {}".format(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))))
			t2.start()
		if not t1.isAlive() :
			logging.info("Start receive_server {}".format(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))))
			t1.start()
		if not t3.isAlive() :
			logging.info("Start receive_server_2 {}".format(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))))
			t3.start()
		try :
			if len(SERVER_RUN) >0 :
				if len(SERVER_RUN) > 1 :
					logging.info("RESTART THREAD : {}".format(SERVER_RUN[1]))
					SERVER_RUN[1].stop()
					SERVER_RUN[1].start()
				else :
					logging.info("RESTART ALL THREAD")
					t1.stop()
					t2.stop()
					t3.stop()
					t1.start()
					t2.start()
					t3.start()
				SERVER_RUN = True
		except:
			logging.debug("SERVER_RUN status : {}".format(str(SERVER_RUN)))
		time.sleep(60)
	t1.close()
	t2.close()
	t3.close()

	logging.info("Server shutdown.")
