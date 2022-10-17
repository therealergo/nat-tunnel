from __future__ import print_function
import socket, select, os, hashlib, time, sys, codecs

NONCE_LEN = 8
PING_PERIOD_SEC = 10
MAX_FAILED_PINGS = 4
TIMEOUT_PERIOD_SEC = 60
MAX_CHUNK_LEN_BYTES = 16 * 1024 * 1024
DO_DETAILED_COMMAND_PRINT = False
CONTROL_SOCKET_RETRY_PERIOD_SEC = 5

PY3 = sys.version_info[0] == 3
if PY3:
	def _b(a, b):
		return bytes(a, b)
else:
	def _b(a, b):
		return bytes(a)

def _get_nonce():
	return codecs.encode(os.urandom(NONCE_LEN), 'hex')

def _hash(str):
	return _b(hashlib.sha256(str).hexdigest(), 'utf-8')

def recvall(conn, n_bytes):
	if n_bytes == 0:
		return b''
	data = b''
	while True:
		data_rx = conn.recv(n_bytes)
		if len(data_rx) == 0:
			raise socket.timeout()
		data += data_rx
		n_bytes -= len(data_rx)
		if n_bytes == 0:
			break
	return data

class NATClient():
	def _reset_control_socket(self, reason):
		print("Control socket failed (" + reason + ")!")
		self.control_socket.close()
		self.control_socket = None
		for conn in self.local_conn_list:
			conn.close()
		self.local_conn_list = []
		self.idx_to_conn_list = {}
		self.conn_to_idx_list = {}

	def _send_command(self, code, conn_idx, data):
		if len(code) != 1:
			raise ValueError("Invalid code!")
		if DO_DETAILED_COMMAND_PRINT:
			print("Command TX: " + str(code) + " idx = " + str(conn_idx) + " len = " + str(len(data)))
		self.control_socket.sendall(code)
		self.control_socket.sendall(conn_idx.to_bytes(4, byteorder="big"))
		self.control_socket.sendall(len(data).to_bytes(4, byteorder="big"))
		if len(data) > 0:
			self.control_socket.sendall(data)

	def __init__(self, secret, upstream_ip, upstream_port, localserv_ip, localserv_port):
		self.secret = secret
		self.localserv_ip = localserv_ip
		self.localserv_port = localserv_port
		self.upstream_ip = upstream_ip
		self.upstream_port = upstream_port
		self.control_socket = None
		self.local_conn_list = []
		self.idx_to_conn_list = {}
		self.conn_to_idx_list = {}

	def setup(self):
		pass

	def doit(self):
		num_unrequited_pings_sent = 0
		is_control_socket_restart = False
		while True:
			try:
				# Open control socket if it isn't already
				if self.control_socket is None:
					print("Opening control socket")
					if is_control_socket_restart:
						time.sleep(CONTROL_SOCKET_RETRY_PERIOD_SEC)
					self.control_socket = socket.socket()
					self.control_socket.connect((self.upstream_ip, self.upstream_port))
					self.control_socket.settimeout(TIMEOUT_PERIOD_SEC)
					nonce = recvall(self.control_socket, NONCE_LEN*2)
					self.control_socket.sendall(_hash(self.secret + nonce))
					is_control_socket_restart = True

				# Wait for any data to be readable, list readable sockets in "a"
				a,b,c = select.select([self.control_socket] + self.local_conn_list, [], [], PING_PERIOD_SEC)

				# Reset connection if too many pings fail
				if (not self.control_socket is None) and (num_unrequited_pings_sent > MAX_FAILED_PINGS):
					self._reset_control_socket("too many unrequited pings")
					continue

				# Nothing for a while, send ping
				if not a:
					if not self.control_socket is None:
						self._send_command(b'P', 0, b'')
				else:

					# Command from control socket
					if self.control_socket in a:
						a.remove(self.control_socket)
						command_c = recvall(self.control_socket, 1)
						command_a = int.from_bytes(recvall(self.control_socket, 4), byteorder="big")
						command_l = int.from_bytes(recvall(self.control_socket, 4), byteorder="big")
						if DO_DETAILED_COMMAND_PRINT:
							print("Command RX: " + str(command_c) + " idx = " + str(command_a) + " len = " + str(command_l))
						command_d = recvall(self.control_socket, command_l)

						# New connection on server side
						if command_c == b'A':
							if command_a in self.idx_to_conn_list.keys():
								raise ValueError("Bad key!")
							conn = socket.socket()
							conn.connect((self.localserv_ip, self.localserv_port))
							self.local_conn_list.append(conn)
							self.idx_to_conn_list[command_a] = conn
							self.conn_to_idx_list[conn] = command_a
							# We don't do anything with the remote address here?

						# Connection failed on the server side
						elif command_c == b'X':
							if command_a in self.idx_to_conn_list.keys():
								conn = self.idx_to_conn_list[command_a]
								self.local_conn_list.remove(conn)
								del self.idx_to_conn_list[command_a]
								del self.conn_to_idx_list[conn]

						# Data from server side
						elif command_c == b'D':
							if command_a in self.idx_to_conn_list.keys():
								conn = self.idx_to_conn_list[command_a]
								conn.sendall(command_d)

						# Ping received, send response
						elif command_c == b'P':
							num_unrequited_pings_sent += 1
							self._send_command(b'R', 0, b'')

						# Ping response received
						elif command_c == b'R':
							num_unrequited_pings_sent = 0
							pass

						# Something else is wrong
						else:
							self._reset_control_socket("invalid command")
							continue

					# Data from local connection
					for local_conn in a:
						if local_conn in self.local_conn_list:
							data = local_conn.recv(MAX_CHUNK_LEN_BYTES)

							# Local connection is dead, stop listening and notify the server of the failure
							if len(data) == 0:
								self._send_command(b'X', self.conn_to_idx_list[local_conn], b'')
								self.local_conn_list.remove(local_conn)
								del self.idx_to_conn_list[self.conn_to_idx_list[local_conn]]
								del self.conn_to_idx_list[local_conn]

							# Pass the data along to the server
							else:
								self._send_command(b'D', self.conn_to_idx_list[local_conn], data)

			except (socket.error) as e:
				self._reset_control_socket("socket error \"" + repr(e) + "\"")

class NATSrv():
	def _isnumericipv4(self, ip):
		try:
			a,b,c,d = ip.split('.')
			if int(a) < 256 and int(b) < 256 and int(c) < 256 and int(d) < 256:
				return True
			return False
		except:
			return False

	def _resolve(self, host, port, want_v4=True):
		if self._isnumericipv4(host):
			return socket.AF_INET, (host, port)
		for res in socket.getaddrinfo(host, port, \
				socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
			af, socktype, proto, canonname, sa = res
			if want_v4 and af != socket.AF_INET: continue
			if af != socket.AF_INET and af != socket.AF_INET6: continue
			else: return af, sa
		return None, None

	def _reset_control_socket(self, reason):
		print("Control socket failed (" + reason + ")!")
		if not self.control_socket is None:
			self.control_socket.close()
			self.control_socket = None
		for conn in self.remote_conn_list:
			conn.close()
		self.remote_conn_list = []
		self.idx_to_conn_list = {}
		self.conn_to_idx_list = {}

	def _send_command(self, code, conn_idx, data):
		if len(code) != 1:
			raise ValueError("Invalid code!")
		if DO_DETAILED_COMMAND_PRINT:
			print("Command TX: " + str(code) + " idx = " + str(conn_idx) + " len = " + str(len(data)))
		self.control_socket.sendall(code)
		self.control_socket.sendall(conn_idx.to_bytes(4, byteorder="big"))
		self.control_socket.sendall(len(data).to_bytes(4, byteorder="big"))
		if len(data) > 0:
			self.control_socket.sendall(data)

	def __init__(self, secret, upstream_listen_ip, upstream_port, client_listen_ip, client_port):
		self.up_port = upstream_port
		self.up_ip = upstream_listen_ip
		self.client_port = client_port
		self.client_ip = client_listen_ip
		self.secret = secret
		self.remote_listen_sock = None
		self.control_listen_sock = None
		self.control_socket = None
		self.hashlen = len(_hash(b''))
		self.remote_conn_list = []
		self.idx_to_conn_list = {}
		self.conn_to_idx_list = {}
		self.conn_to_idx_next = 0

	def setup(self):
		print("Listening for control socket")
		af, sa = self._resolve(self.client_ip, self.client_port)
		self.remote_listen_sock = socket.socket(af, socket.SOCK_STREAM)
		self.remote_listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.remote_listen_sock.bind((sa[0], sa[1]))
		self.remote_listen_sock.listen(1)
		af, sa = self._resolve(self.up_ip, self.up_port)
		self.control_listen_sock = socket.socket(af, socket.SOCK_STREAM)
		self.control_listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.control_listen_sock.bind((sa[0], sa[1]))
		self.control_listen_sock.listen(1)

	def doit(self):
		num_unrequited_pings_sent = 0
		while True:
			try:
				# Wait for any data to be readable, list readable sockets in "a"
				if self.control_socket is None:
					a,b,c = select.select([self.control_listen_sock], [], [], PING_PERIOD_SEC)
				else:
					a,b,c = select.select([self.remote_listen_sock, self.control_listen_sock, self.control_socket] + self.remote_conn_list, [], [], PING_PERIOD_SEC)

				# Reset connection if too many pings fail
				if (not self.control_socket is None) and (num_unrequited_pings_sent > MAX_FAILED_PINGS):
					self._reset_control_socket("too many unrequited pings")
					continue

				# Nothing for a while, send ping
				if not a:
					if not self.control_socket is None:
						self._send_command(b'P', 0, b'')
				else:

					# New control socket connection
					if self.control_listen_sock in a:
						a.remove(self.control_listen_sock)
						conn, addr = self.control_listen_sock.accept()
						conn.settimeout(TIMEOUT_PERIOD_SEC)
						if self.control_socket is None:
							nonce = _get_nonce()
							conn.sendall(nonce)
							secure = recvall(conn, len(_hash(b'')))
							if secure == _hash(self.secret + nonce):
								self.control_socket = conn
								print("Control socket connected")
							else:
								print("Control socket security failure!")
								conn.close()
						else:
							print("Control socket already present!")
							conn.close()

					# New remote connection
					if self.remote_listen_sock in a:
						a.remove(self.remote_listen_sock)
						conn, addr = self.remote_listen_sock.accept()

						# We have no control socket, kill the connection
						if self.control_socket is None:
							print("Cannot accept, no control socket!")
							conn.close()

						# Start listening to this connection and notify the client of the new connection
						else:
							addr_bytes = str.encode(str(addr))
							while self.conn_to_idx_next in self.idx_to_conn_list.keys():
								self.conn_to_idx_next += 1
							print("Remote connection accepted: addr = " + str(addr) + " idx = " + str(self.conn_to_idx_next))
							self.remote_conn_list.append(conn)
							self.idx_to_conn_list[self.conn_to_idx_next] = conn
							self.conn_to_idx_list[conn] = self.conn_to_idx_next
							self._send_command(b'A', self.conn_to_idx_list[conn], addr_bytes)

					# Command from control socket
					if self.control_socket in a:
						a.remove(self.control_socket)
						command_c = recvall(self.control_socket, 1)
						if len(command_c) != 1:
							self._reset_control_socket("socket read failure")
							continue
						else:
							command_a = int.from_bytes(recvall(self.control_socket, 4), byteorder="big")
							command_l = int.from_bytes(recvall(self.control_socket, 4), byteorder="big")
							if DO_DETAILED_COMMAND_PRINT:
								print("Command RX: " + str(command_c) + " idx = " + str(command_a) + " len = " + str(command_l))
							command_d = recvall(self.control_socket, command_l)

							# Data from client side
							if command_c == b'D':
								if command_a in self.idx_to_conn_list.keys():
									conn = self.idx_to_conn_list[command_a]
									if not conn is None:
										conn.sendall(command_d)

							# Connection killed from client side
							elif command_c == b'X':
								if command_a in self.idx_to_conn_list.keys():
									conn = self.idx_to_conn_list[command_a]
									self.remote_conn_list.remove(conn)
									del self.idx_to_conn_list[command_a]
									del self.conn_to_idx_list[conn]

							# Ping received, send response
							elif command_c == b'P':
								num_unrequited_pings_sent += 1
								self._send_command(b'R', 0, b'')

							# Ping response received
							elif command_c == b'R':
								num_unrequited_pings_sent = 0
								pass

							# Something else is wrong
							else:
								self._reset_control_socket("invalid command")
								continue

					# Data from remote connection
					for remote_conn in a:
						if remote_conn in self.remote_conn_list:
							data = remote_conn.recv(MAX_CHUNK_LEN_BYTES)

							# Remote connection is dead, stop listening and notify the client of the failure
							if len(data) == 0:
								self._send_command(b'X', self.conn_to_idx_list[remote_conn], b'')
								self.remote_conn_list.remove(remote_conn)
								del self.idx_to_conn_list[self.conn_to_idx_list[remote_conn]]
								del self.conn_to_idx_list[remote_conn]

							# Pass the data along to the client
							else:
								self._send_command(b'D', self.conn_to_idx_list[remote_conn], data)
			
			except (socket.error) as e:
				self._reset_control_socket("socket error \"" + repr(e) + "\"")


if __name__ == "__main__":
	import argparse
	desc=(
		"NAT Tunnel v0.01\n"
		"----------------\n"
		"If you have access to a server with public IP and unfiltered ports\n"
		"you can run NAT Tunnel (NT)  server on the server, and NT client\n"
		"on your box behind NAT.\n"
		"the server requires 2 open ports: one for communication with the\n"
		"NT client (--admin), the other for regular clients to connect to\n"
		"(--public: this is the port you want your users to use).\n"
		"\n"
		"The NT client opens a connection to the server's admin ip/port.\n"
		"As soon as the server receives a new connection, it signals the\n"
		"NT client, which then creates a new tunnel connection to the\n"
		"server, which is then connected to the desired service on the\n"
		"NT client's side (--local)\n"
		"\n"
		"The connection between NT Client and NT Server on the admin\n"
		"interface is protected by a shared secret against unauthorized use.\n"
		"An adversary who can intercept packets could crack the secret\n"
		"if it's of insufficient complexity. At least 10 random\n"
		"characters and numbers are recommended.\n"
		"\n"
		"Example:\n"
		"You have a HTTP server listening on your local machine on port 80.\n"
		"You want to make it available on your cloud server/VPS/etc's public\n"
		"IP on port 7000.\n"
		"We use port 8000 on the cloud server for the control channel.\n"
		"\n"
		"Server:\n"
		"    %s --mode server --secret s3cretP4ss --public 0.0.0.0:7000 --admin 0.0.0.0:8000\n"
		"Client:\n"
		"    %s --mode client --secret s3cretP4ss --local localhost:80 --admin example.com:8000\n"
	) % (sys.argv[0], sys.argv[0])
	if len(sys.argv) < 2 or (sys.argv[1] == '-h' or sys.argv[1] == '--help'):
		print(desc)
	parser = argparse.ArgumentParser(description='')
	parser.add_argument('--secret', help='shared secret between natserver/client', type=str, default='', required=True)
	parser.add_argument('--mode', help='work mode: server or client', type=str, default='server', required=True)
	parser.add_argument('--public', help='(server only) ip:port where we will listen for regular clients', type=str, default='0.0.0.0:8080', required=False)
	parser.add_argument('--local', help='(client only) ip:port of the local target service', type=str, default="localhost:80", required=False)
	parser.add_argument('--admin', help='ip:port tuple for admin/upstream/control connection', type=str, default="0.0.0.0:8081", required=False)
	args = parser.parse_args()
	adminip, adminport = args.admin.split(':')
	if args.mode == 'server':
		clientip, clientport = args.public.split(':')
		srv = NATSrv(_b(args.secret, 'utf-8'), adminip, int(adminport), clientip, int(clientport))
		srv.setup()
		srv.doit()
	else:
		localip, localport = args.local.split(':')
		cl = NATClient(_b(args.secret, 'utf-8'), adminip, int(adminport), localip, int(localport))
		cl.setup()
		cl.doit()
