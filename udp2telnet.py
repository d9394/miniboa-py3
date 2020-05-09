#!/usr/bin/env python3

import threading
import datetime,time
import re
from miniboa import TelnetServer, colorize
import socket 
import WSJTXClass
import logging

threads = {}
service = {
	"1":"spot_server",
	"2":"wsjtx_udp",
	"3":"pydecoder_udp",
}

IDLE_TIMEOUT = 3600
CLIENT_LIST = []
DecoderArray = {}
ADMIN_PWD = "Aa1234567"        #do not use "'=, in password

def pydecoder_udp(my_thread) :
	"""
	receive udp packet from my ft8-deocder
	each message format is : 150430  -6  1.1 2724 ~  CQ BD4QA OM91              
	Identify each station is send a line before any message : Start Decode
	"""
	try:
		mSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		mSocket.bind(("",5556)) 
	except Exception as e:
		logging.error("bind 5556 error {}".format(e))
	else :
		logging.debug("Listening for Plante UDP ({}) log on port {}. CTRL-C to break.".format(my_thread, "5556"))
		try:
			while True:
				if my_thread not in SERVER_RUN :
					logging.info("Restart pydecoder_udp thread by %s" % SERVER_RUN)
					return
				fileContent, (remoteHost, remotePort) = mSocket.recvfrom(1024)
				DecoderStation = ("{}:{}:UDP".format(remoteHost, remotePort))
				decode_2(fileContent, DecoderStation)
		except Exception as e :
			logging.info("UDP receive error (%s) %s" % (e, fileContent))

def decode_2(Content, Station):
	if Station not in DecoderArray :
		DecoderArray.update({Station : ""} )
		logging.info("New Station %s" % Station)
	try:
		msg = Content.decode('utf-8')
		if msg[:11] == "<parameters" :
			msg = adif_spot(msg)
		elif msg[:12] == "Start Decode" :
			if DecoderArray[Station] != msg.replace("Start Decode ", "") :
				DecoderArray[Station] = msg.replace("Start Decode ", "")
				for station in list(DecoderArray.keys()) :
					if DecoderArray[station] == msg.replace("Start Decode ", "") :
						if station != Station :
							del DecoderArray[station]
		elif msg[:16] == "Redpitaya Decode" :
			if DecoderArray[Station] != msg.replace("Redpitaya Decode ", "") :
				DecoderArray[Station] = msg.replace("Redpitaya Decode ", "")
				for i in list(DecoderArray.keys()) :
					if DecoderArray[i] == msg.replace("Redpitaya Decode ", "") :
						if i != Station :
							del DecoderArray[i]
		elif msg[:10] == "End Decode" :
			return
		else :
			broadcast(msg[:51] + DecoderArray[Station] + '\n')
	except :
		logging.error("UDP packet error (%s) : %s" % (DecoderArray[Station],msg))
	return

def adif_spot(adif_text):					#No used function at this time
	adif_data = {}
	resutl = ""
	"""
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
	"""
	return result

def wsjtx_udp(my_thread):
	"""
	receive message from JTDX or WSJTX program UDP packet
	"""
	try:
		mSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		mSocket.bind(("",5555)) 
	except Exception as e:
		logging.error("bind 5555 error {}".format(e))
	logging.debug("Listening for WSTJ-X UDP ({}) log on port {}. CTRL-C to break.".format(my_thread, "5555"))
	while True:
		if my_thread not in SERVER_RUN:
			logging.info("Restart wsjtx_udp thread by %s" % SERVER_RUN)
			return

		fileContent, (remoteHost, remotePort) = mSocket.recvfrom(1024)
		DecoderStation = ("{}:{}:JTDX".format(remoteHost, remotePort))
		try:
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
					logging.info("New Station %s" % DecoderStation)
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
		except :
			logging.error("WSJTX UDP error (%s): %s" % (DecoderArray[DecoderStation],fileContent))

def spot_server(my_thread):
	"""
	Create a telnet server with a port, address, a function to call with new connections
	and one to call with lost connections.
	"""
	telnet_server = TelnetServer(
		port=7300,
		address='',
		on_connect=on_connect,
		on_disconnect=on_disconnect,
		timeout = .05
		)
	logging.debug("Listening for SPOT ({}) connections on port {}. CTRL-C to break.".format(my_thread, telnet_server.port))
	while 1:
		if my_thread not in SERVER_RUN :
			logging.info("Restart spot_server thread by %s" % SERVER_RUN)
			return
		telnet_server.poll()
		kick_idle() 
		process_clients()
		
def on_connect(client):
	"""
	Sample on_connect function.
	Handles new connections.
	"""
	logging.info("Opened connection to {}".format(client.addrport()))
	#broadcast("{} joins the conversation.\n".format(client.addrport()))
	CLIENT_LIST.append(client)
	client.send("Welcome to the Spot Server, {}.\n".format(client.addrport()))

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
		if client.active :
			# If the client sends input echo it to the chat room
			if client.callsign == "" :
				client.send("Please input your Callsign :\n")
				client.callsign = "-"
			elif client.filter == "" and client.callsign != "-" :
				client.send("Please select frequency , example : fe=14074000\n")
				client.filter = "-"
			if client.cmd_ready :
				chat(client)

def chat(client):
	"""
	Echo whatever client types to everyone.
	"""
	msg = client.get_command()
	if msg is not None :
		msg = msg.upper().replace(" ", "")
		logging.info("{} says '{}'".format(client.addrport(), msg))
		if len(msg.split())>0 :
			command = msg.split("=")
			if command[0] == "HELP" or command[0] == "?":
				send_msg = "sa=ba7ib : filter only msg from station ba7ib\n"
				send_msg += "fe=14074000 : filter only frequency is 14074000\n"
				send_msg += "ca=y : filter only callsign begin with y\n"
				send_msg += "mo=ft8 : filter only mode is ft8\n"
				send_msg += "cq : only cq call will display\n"
				send_msg += "ck : check your filter\n"
				send_msg += "nf : clear all filter\n"
				send_msg += "nc : toggle color True/False\n"
				send_msg += "stations : list all register report station\n"
				send_msg += "clients : list all listen clients\n"
				send_msg += "bye : disconnect\n"
				client.send(send_msg)
			elif command[0] in ['SA', 'FE', 'CA', "MO", "CQ"] :
				if client.filter == "-" :
					client.filter = msg.replace(" ", "")
				else :
					client.filter = client.filter + ", " + msg.replace(" ", "")
				client.send(" your filter is : {}\n".format( client.filter ))
			elif command[0] == "NF" :
				client.filter = ""
				client.send("No filters\n")
			elif command[0] == "NC" :
				client.color = not client.color
				client.send("Set Colorful %s\n" % client.color)
			elif command[0] == "CK" :
				client.send("{} filter is : {}\n".format( client.callsign,  client.filter ))
			elif command[0] == 'BYE':			# bye = disconnect
				client.active = False
			elif command[0] == "THREADS" : # check threading status
				send_msg = "Telnet Server Thread List  :\n"
				for i in threads :
					send_msg += service[threads[i]] + "(" + threads[i] + ") is  : " + str(i.isAlive()) + '\n'
				client.send(send_msg)
			elif command[0] == 'SHUTDONW':			# shutdown == stop the server
				if command[1] == ADMIN_PWD :
					SERVER_RUN.append("STOP")
				else :
					client.send("Admin Password Error\n".format(SERVER_RUN))
			elif command[0] == 'RESTART' :			# restart == restart thread
				if command[1] == ADMIN_PWD :
					for i in command[2].split(",") :
						if i in SERVER_RUN:
							SERVER_RUN.remove(i)
					client.send("wait 60s for {}\n".format(SERVER_RUN))
				else :
					client.send("Admin Password Error\n".format(SERVER_RUN))
			elif command[0] == 'CLIENTS' :			# clients == list all clients
				i = 0
				for guest in CLIENT_LIST :
					client.send("{} from {} filter {} ({}s)\n".format(guest.callsign, guest.addrport(), guest.filter, int(guest.duration())))
					i += 1
				client.send("Total clints : {}\n".format(i))
			elif command[0] == 'KILL' :			# kill == kick out client
				if command[1] == ADMIN_PWD :
					try:
						for guest in CLIENT_LIST :
							if guest.addrport() == command[2] :
								guest.active = False
								client.send("\n")
								break
					except :
						logging.error("kickout command error %s" % msg)
				else :
					client.send("Admin Password Error\n".format(SERVER_RUN))
			elif command[0] == 'STATIONS' :			# stations == list all report stations
				for station in DecoderArray :
					client.send("{} : {}\n".format(station, DecoderArray[station]))
			elif client.callsign == "" or client.callsign == "-" :
				CallSign_reg = r'([A-Z]{1,2}|[0-9][A-Z])([0-9])([A-Z]{1,3})'
				try:
					if re.match(CallSign_reg, command[0] , re.I).span()[0] == 0 :
						logging.info("{} logon the server".format(command[0]))
						client.callsign = command[0]
						client.send("Wellcome {} logon @ {}\n".format(command[0], client.addrport()))
				except :
					client.send("Callsign Error. Please input again\n")
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
		if client.idle() > IDLE_TIMEOUT and client.callsign == "-" :
			logging.info("Kicking idle lobby client from {}".format(client.addrport()))
			client.active = False
			
def calu_dis(tar_grid):
	return int(pow((pow(abs(ord(tar_grid[:1])- ord("O")),2) + pow(abs(ord(tar_grid[1:2])-ord("L")),2)),0.5))

def broadcast(msg):
	"""
	Send msg to every client.
	"""
	colorful = ("^r", "^g", "^y", "^b", "^m", "^c", "^w")
	for client in CLIENT_LIST:
		if client.callsign != "" and client.callsign != "-" and client.filter != "" and client.filter != "-" :
			detail_msg = msg.split()
			msg_color=""
			if client.color :
				char_sum = 0
				for i in "-".join(detail_msg[-1].split("-")[2:]) :
					char_sum += ord(i)
				msg_color = colorful[int(char_sum % 7)]
				if detail_msg[5] == "CQ" :
					msg_color = "^G"
					grid = detail_msg[-2]
					if len(grid) == 4 :
						DIS = calu_dis(grid)
						if DIS > 7 :
							msg_color = "^R" 
						elif DIS > 3 and DIS <= 7 :
							msg_color = "^Y"
#				else :
#					msg_color += "^w"
			if len(client.filter) > 0 :
				if client.filter.find("=*") == -1 :
					for detail in client.filter.split(", ") :
						filter = detail.split("=")
						if filter[0] == "SA" :
							if detail_msg[-1].split("-")[2] != filter[1] :
								msg=""
						elif filter[0] == "FE" :
							if detail_msg[-1].split("-")[0] != filter[1] :
								msg=""
						elif filter[0] == "CQ" :
							if detail_msg[5] != "CQ" :
								msg=""
						elif filter[0] == "CA" :
							if " ".join(detail_msg[5:-1]).find(filter[1]) == -1 :
								msg=""
						elif filter[0] == "MO" :
							if detail_msg[-1].split("-")[1] != filter[1] :
								msg=""
						if msg == "" :
							break
			if msg != "" :
				if client.last_send != detail_msg[0] :
					client.send("          .-.-.            .-.-.             .-.-.\n")
					client.last_send = detail_msg[0]
				client.send(colorize(msg_color + msg))

if __name__ == '__main__':
	# Simple chat server to demonstrate connection handling via the
	# async and telnet modules.
	global SERVER_RUN
	logging.basicConfig(level=logging.INFO,#控制台打印的日志级别
		filename='/tmp/udp2telnet.log',
		filemode='w',##模式，有w和a，w就是写模式，每次都会重新写日志，覆盖之前的日志
		#a是追加模式，默认如果不写的话，就是追加模式
		format='%(asctime)s - [line:%(lineno)d] - %(levelname)s: %(message)s'    #日志格式
	)
	SERVER_RUN =[]
	for i in service:
		if service[i] == "spot_server" :
			telnet_thread = threading.Thread(target=spot_server, args=(i,))
		elif service[i] == "wsjtx_udp" :
			telnet_thread = threading.Thread(target=wsjtx_udp, args=(i,))
		elif service[i] == "pydecoder_udp" :
			telnet_thread = threading.Thread(target=pydecoder_udp, args=(i,))
		threads.update({telnet_thread:i})
		SERVER_RUN.append(i)
	for i in threads:
#		threads[i].setDaemon(True)
		i.start()

	# Server Loop

	while "STOP" not in SERVER_RUN :
		for i in threads:
			if not i.isAlive() :
				r = threads[i]
				del threads[i]
				logging.info("Retart {} thread @ {}".format(r,time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))))
				if service[r] == "spot_server" :
					telnet_thread = threading.Thread(target=spot_server, args=(r,))
				elif service[r] == "wsjtx_udp" :
					telnet_thread = threading.Thread(target=wsjtx_udp, args=(r,))
				elif service[r] == "pydecoder_udp" :
					telnet_thread = threading.Thread(target=pydecoder_udp, args=(r,))
				threads.update({telnet_thread:r})
				telnet_thread.start()
				if r not in SERVER_RUN :
					SERVER_RUN.append(r)
		time.sleep(5)

	logging.info("Server shutdown.")
