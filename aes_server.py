#!/usr/bin/python
import sys, socket, select, json
import getopt, base64, binascii
import commands

from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
from Crypto.Cipher import AES
from Crypto import Random

DEBUG = False
USE_OPENSSL = False
SAVE_DETAIL = False
LISTEN_PORT = int(80)
ENCRYPT_COUNT = int(1)
AES_KEY = "1234567890abcdef"
AES_BLOCK_SIZE = 16
AES_MODE = AES.MODE_CBC
AES_MODE_STR = "cbc"
AES_IV_STR = ""
OPENSSL_AES_MODE = "aes-256-cbc"
OPENSSL_PASSWORD = "1234567890"


AES_PAD = lambda s: s + (AES_BLOCK_SIZE - len(s) % AES_BLOCK_SIZE) * chr(AES_BLOCK_SIZE - len(s) % AES_BLOCK_SIZE) 
AES_UNPAD = lambda s : s[:-ord(s[len(s)-1:])]

def ConstructErrorResponse(err):
	lenth_str = "Content-Length: "+str(len(err))+"\r\n\r\n"
	err_header = "HTTP/1.1 400 \r\nContent-Type: text/html\r\n"+lenth_str+err
	return err_header
	
def ConstructResponse(payload):
	lenth_str = "Content-Length: "+str(len(payload))+"\r\n\r\n"
	response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"+lenth_str+payload
	return response

class AESCipher:
	def __init__(self, key, bs):
		self.key = key
		self.bs = bs
	
	def encrypt(self, text):
		if USE_OPENSSL:
			cmd = "echo -n \""+text+"\" | openssl enc -" + OPENSSL_AES_MODE+" -pass pass:"+OPENSSL_PASSWORD+" | openssl base64"
			if DEBUG:
				print cmd
			ret, enc = commands.getstatusoutput(cmd)
		else:
			text = AES_PAD(text)
			if (DEBUG):
				print "PAD text size is", len(text)
				print "PAD text is", text
				print "AES.block size is", AES.block_size
			if (len(AES_IV_STR)):
				iv = AES_IV_STR
			else:
				iv = Random.new().read(AES.block_size)
			cipher = AES.new(self.key, AES_MODE, iv)
			if (len(AES_IV_STR)):
				enc = base64.b64encode(cipher.encrypt(text))
			else:
				enc = base64.b64encode(iv + cipher.encrypt(text))
		if SAVE_DETAIL:
			global ENCRYPT_COUNT
			ENCRYPT_COUNT = ENCRYPT_COUNT+1
			print str(ENCRYPT_COUNT)+". text: "+text+" ciper: "+enc
		return enc

	def decrypt(self, enc):
		if (DEBUG):
			print "enc is",enc
		if USE_OPENSSL:
			cmd = "echo \""+enc+ "\" | openssl base64 -d | openssl enc -"+ OPENSSL_AES_MODE+" -pass pass:"+OPENSSL_PASSWORD+" -d"
			if DEBUG:
				print cmd
			ret, text = commands.getstatusoutput(cmd)
			return text
		else:
			enc = base64.b64decode(enc)
			if (len(AES_IV_STR)):
				iv = AES_IV_STR
				cipher = AES.new(self.key, AES_MODE, iv)
				return AES_UNPAD(cipher.decrypt(enc))
			else:
				iv = enc[:AES.block_size]
				cipher = AES.new(self.key, AES_MODE, iv)
				return AES_UNPAD(cipher.decrypt(enc[AES.block_size:]))

class HTTPRequest(BaseHTTPRequestHandler):
	def __init__(self, request_text):
		self.rfile = StringIO(request_text)
		self.raw_requestline = self.rfile.readline()
		self.error_code = self.error_message = None
		self.parse_request()

	def send_error(self, code, message):
		self.error_code = code
		self.error_message = message
	
		
class HTTPHeaders():
	def __init__(self, data):
		self.parsed_http = HTTPRequest(data)
		self.uri = ""
		self.params = ""
		
		if ('?' in self.parsed_http.path):
			self.uri, param_str = self.parsed_http.path.split('?')
			params = param_str.split('&')
			self.params = {}
			for str in params:
				name, value = str.split('=',1)
				self.params[name] = value
		else:
			self.uri = self.parsed_http.path
		if (DEBUG):
			self.show_headers()
		
	def show_headers(self):
		parsed_http = self.parsed_http
		headers = parsed_http.headers
		print "Command:", parsed_http.command
		print "Request_version:", parsed_http.request_version
		print "Requestline:", parsed_http.requestline
		print "Path:", parsed_http.path
		print "URI:", self.uri
		print "Params:", self.params
		print "Headers:" 
		for (h,v) in  parsed_http.headers.items():
			print "\t", h, ": ", v
	
	def get_header_value(self, header_name):
		headers = self.parsed_http.headers
		if (not headers.has_key(header_name)):
			return None
		return headers[header_name]
		
	def get_param_value(self, param):
		if param in self.params:
			return self.params[param]
		else:
			return None			
	
		
class HTTPClient():
	def __init__(self, socket, addr, aes):
		self.header = HTTPRequest("")
		self.socket = socket
		self.addr = addr
		self.aes = aes
		self.fileno = socket.fileno()
		self.header_is_ok = False
		self.request = ""
		self.data_len = "0"
			
	def join_epoll(self, epoll):
		if (DEBUG):
			print self.addr, "is connected"
		self.socket.setblocking(0)
		epoll.register(self.fileno, select.EPOLLIN|select.EPOLLHUP)
		self.epoll = epoll
	
	def leave_epoll(self):
		if (DEBUG):
			print self.addr, "is disconnected"
		self.epoll.unregister(self.fileno)
		self.socket.close();
		
	def get_fileno(self):
		return self.fileno
		
	def parse_http_header(self):
		if ("\r\n\r\n" in self.request):
			sep_index = self.request.find("\r\n\r\n")
			sep_index += len("\r\n\r\n")
		elif ("\n\n" in self.request):
			sep_index = self.request.find("\n\n")
			sep_index += len("\n")
		else:
			print "Unexpected error"
			exit(-1)
		
		header = self.request[:sep_index]
		self.request = self.request[sep_index:]
		self.http_headers = HTTPHeaders(header)
		self.header_is_ok = True
		
	def read_data(self):
		data = self.socket.recv(1024)
		if (0 == len(data)):
			self.leave_epoll()
		else :
			self.request += data
			
			if (not self.header_is_ok):
				if (self.header_is_completed()):
					self.parse_http_header()
					self.data_len = self.http_headers.get_header_value("Content-Length")
					if (None == self.data_len):
						self.data_len = "0"
			
			data_len = int(self.data_len)
			if (self.header_is_ok and data_len <= len(self.request)):
				json_data = self.request[:data_len]
				self.request = self.request[data_len:]
				if (DEBUG):
					print "Payload:", json_data
				
				if (data_len):
					try:
						json_data = json.loads(json_data)
					except ValueError:
						print "Invalid json data", json_data
				
				# Get action
				action = self.http_headers.get_param_value("action")
				if ("enc" == action):
					text = self.http_headers.get_param_value("text")
					if (text):
						ciper = self.aes.encrypt(text)
						payload = {}
						payload["text"] = text
						payload["ciper"] = ciper
						jason_data = json.dumps(payload)
						response = ConstructResponse(jason_data)
					else:
						response = ConstructErrorResponse("No text param")
				elif ("dec" == action):
					ciper = self.http_headers.get_param_value("ciper")
					if (ciper):
						text = self.aes.decrypt(ciper)
						payload = {}
						payload["text"] = text
						payload["ciper"] = ciper
						jason_data = json.dumps(payload)
						response = ConstructResponse(jason_data)
					else:
						response = ConstructErrorResponse("No ciper param")
				else:
					if (DEBUG):
						print "No supported operation"
					response = ConstructErrorResponse("No supported aciton or no specify action")
					
				self.socket.send(response)
				self.leave_epoll()			
			
	def header_is_completed(self):
		if (("\r\n\r\n" in self.request) or ("\n\n" in self.request)):
			return True
		else:
			return False
			
def usage():
	print "-h: Show the help"
	print "-l: Specify listen port"
	print "-k: Specify AES key"
	print "-e: Specify AES encrypt mode. default is cbc"
	print "-s: Specify AES block size"
	print "-v: Specify AES IV. default is random string"
	print "-o: Use openssl to encrypt or decrypt. Must specify password too"
	print "-p: Specify password. Only used with openssl"
	print "-m: Specify openssl enc mode. Only used with openssl"
	print "-t: Save the encrypt count and record"
	print "-d: Debug mode"

if __name__ == "__main__":

	try:
		opts, args = getopt.getopt(sys.argv[1:], "hl:k:e:s:v:p:tdo")
	except getopt.GetoptError as err:
		print str(err)
		usage()
		sys.exit(1)
	for o, a in opts:
		if (o == "-h"):
			usage()
			sys.exit()
		elif (o == "-l"):
			LISTEN_PORT = int(a)
		elif (o == "-k"):
			AES_KEY = a
			if (len(AES_KEY) != 16 and len(AES_KEY) != 24 and len(AES_KEY) != 32):
				print "AES key must be either 16, 24, or 32 bytes long"
				sys.exit(1)
		elif (o == "-e"):
			if ("ecb" == a):
				AES_MODE = AES.MODE_ECB
			elif ("cbc" == a):
				AES_MODE = AES.MODE_CBC
			elif ("cfb" == a):
				AES_MODE == AES.MODE_CFB
			elif ("ofb" == a):
				AES_MODE == AES.MODE_OFB
			elif ("ctr" == a):
				AES_MODE == AES.MODE_CTR
			else:
				print "Only support (ecb|cbc|cfb|ofb|ctr)"
				sys.exit(1)
			AES_MODE_STR = a
		elif (o == "-s"):
			AES_BLOCK_SIZE = int(a)
		elif (o == "-v"):
			AES_IV_STR = a
			if (len(AES_IV_STR) != 16):
				print "AES IV size must be 16"
				sys.exit(1)
		elif (o == "-p"):
			OPENSSL_PASSWORD = a
		elif (o == "-m"):
			OPENSSL_AES_MODE = a
		elif (o == "-o"):
			USE_OPENSSL = True
		elif (o == "-t"):
			SAVE_DETAIL = True
			ENCRYPT_COUNT = int(0)
		elif (o == "-d"):
			DEBUG = True
		else:
			assert False, "unhandled option"
	
	if (USE_OPENSSL and 0 == len(OPENSSL_PASSWORD)):
		print "Must set password when use openssl"
		sys.exit(1)

	master_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	master_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	master_socket.bind(('', LISTEN_PORT))
	master_socket.listen(5)
	master_socket.setblocking(0)
	
	ass_ciper = AESCipher(AES_KEY, AES_BLOCK_SIZE)
	
	if not USE_OPENSSL:
		if DEBUG:
			print "Only support aes-128. Please use -o option to use openssl if you want to use other bits"
	
	if (DEBUG):
		print "The AES server is listenning the", LISTEN_PORT, "port now"
		print "The AES key is", AES_KEY, binascii.b2a_hex(AES_KEY)
		print "The AES mode is", AES_MODE_STR
		print "The AES block size is", AES_BLOCK_SIZE
		if (len(AES_IV_STR)):
			print "The AES iv is", AES_IV_STR, binascii.b2a_hex(AES_IV_STR)
		else:
			print "The AES iv uses random string"
		if (USE_OPENSSL):
			print "Use openssl to encrypt/decrypt"
			print "password is", OPENSSL_PASSWORD
			print "openssl aes mode is", OPENSSL_AES_MODE
		if (SAVE_DETAIL):
			print "Save details"

	epoll = select.epoll()
	epoll.register(master_socket.fileno(), select.EPOLLIN)

	try:
		http_clients = {}
		
		while (True):
			request = ""
			events = epoll.poll(3) # wait 3 seconds
			for fileno, event in events:
				if fileno == master_socket.fileno():
					worker_socket, client_addr = master_socket.accept()
					http_client = HTTPClient(worker_socket, client_addr, ass_ciper)
					http_client.join_epoll(epoll)
					http_clients[http_client.get_fileno()] = http_client
				elif (event & (select.EPOLLIN|select.EPOLLHUP)):
					http_client = http_clients[fileno]
					http_client.read_data()
				else:
					print "Unhandled event", event
	finally:
		epoll.unregister(master_socket.fileno())
		master_socket.close();

	
