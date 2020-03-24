#!/usr/bin/env python3

import logging
import socket 
import threading
import datetime,time
import re
from miniboa import TelnetServer
import WSJTXClass

IDLE_TIMEOUT = 300
CLIENT_LIST = []
SERVER_RUN = True

def on_connect(client):
	"""
	Sample on_connect function.
	Handles new connections.
	"""
	logging.info("Opened connection to {}".format(client.addrport()))
	broadcast("{} joins the conversation.\n".format(client.addrport()))
	CLIENT_LIST.append(client)
	client.send("Welcome to the Spot Server, {}.\n".format(client.addrport()))

def on_disconnect(client):
	"""
	Sample on_disconnect function.
	Handles lost connections.
	"""
	logging.info("Lost connection to {}".format(client.addrport()))
	CLIENT_LIST.remove(client)
	broadcast("{} leaves the conversation.\n".format(client.addrport()))

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
	logging.info("{} says '{}'".format(client.addrport(), msg))

	for guest in CLIENT_LIST:
		if guest != client:
			guest.send("{} says '{}'\n".format(client.addrport(), msg))
		else:
			guest.send("You say '{}'\n".format(msg))

	cmd = msg.lower()
	# bye = disconnect
	if cmd == 'bye':
		client.active = False
	# shutdown == stop the server
	elif cmd == 'shutdown':
		SERVER_RUN = False

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
		client.send(msg)

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

def receive_udp():
	DecoderArray = {}
	try:
		mSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		mSocket.bind(("",5555)) 
	except Exception as e:
		print("bind 5555 error %s" % e)
	logging.info("Listening for UDP ADIF log on port {}. CTRL-C to break.".format("5555"))
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
				logging.info("Heartbeat : {} @ {}".format(dataDecode, DecoderArray[DecoderStation]))
			except :
				logging.info("Heartbeat : {} @ ".format(dataDecode))

		elif NewPacket.PacketType == 1:
			StatusPacket = WSJTXClass.WSJTX_Status(fileContent, NewPacket.index)
			StatusPacket.Decode()
			dataDecode = ("{:08}-{}-{}".format(StatusPacket.Frequency, StatusPacket.Mode, StatusPacket.DECall))
			#StatusPacket.Decoding
			if DecoderStation not in DecoderArray :
				DecoderArray.update({DecoderStation : ""} )
			if StatusPacket.Decoding and DecoderArray[DecoderStation] != dataDecode:
				DecoderArray[DecoderStation] = dataDecode
			logging.info("Status : {} {} @ {}".format(dataDecode, StatusPacket.Decoding, DecoderArray[DecoderStation]))

		elif NewPacket.PacketType == 2:
			DecodePacket = WSJTXClass.WSJTX_Decode(fileContent, NewPacket.index)
			DecodePacket.Decode()
			# can use PyQt4.QtCore.QTime for this as well!
			s = int(  (DecodePacket.Time/1000) % 60 )
			m = int( ((DecodePacket.Time/(1000*60) ) %60 ) )
			h = int( ((DecodePacket.Time/(1000*60*60)) %24))
			dataDecode = ("{:02}:{:02}:{:02} {:>3} {:4.1f} {:>4} {} {}".format(h,m,s,DecodePacket.snr,DecodePacket.DeltaTime,DecodePacket.DeltaFrequency,DecodePacket.Mode,DecodePacket.Message))
			try :
				logging.info("Decode : {} @ {}".format(dataDecode, DecoderArray[DecoderStation]))
			except :
				logging.info("Decode : {} @".format(dataDecode))
#			self.DecodeCount += 1
			# now we need to send it to the UI
			msg = dataDecode + ' ' + DecoderArray[DecoderStation]
			broadcast(msg)

		elif NewPacket.PacketType == 3:
			logging.info("PacketType = 3")

		elif NewPacket.PacketType == 5:
			LoggedPacket = WSJTXClass.WSJTX_Logged(fileContent, NewPacket.index)
			LoggedPacket.Decode()
			logging.info("LoggedPacket : {}".format(LoggedPacket))
		


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
	logging.info("Listening for SPOT connections on port {}. CTRL-C to break.".format(telnet_server.port))
	while SERVER_RUN:
		telnet_server.poll()
		kick_idle() 
		process_clients()
	
if __name__ == '__main__':

	# Simple chat server to demonstrate connection handling via the
	# async and telnet modules.

	logging.basicConfig(level=logging.DEBUG)

	t1 = threading.Thread(target=receive_udp, name='receive_udp_server')
	t2 = threading.Thread(target=spot_server, name='telnet_server')
	# Server Loop
	while SERVER_RUN:
		if not t2.isAlive() :
			logging.info("Start telnet_server {}".format(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))))
			t2.start()
		if not t1.isAlive() :
			logging.info("Start receive_server {}".format(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))))
			t1.start()
		time.sleep(300)
	t1.close()
	t2.close()

	logging.info("Server shutdown.")
