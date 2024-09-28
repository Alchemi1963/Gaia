import ssl
from socket import gethostname, socket, AF_INET, SOCK_DGRAM

from ldap3 import Server, Connection, ALL, Tls


def get_local_ip():
	s = socket(AF_INET, SOCK_DGRAM)
	try:
		# doesn't even have to be reachable
		s.connect(('10.255.255.255', 1))
		ip = s.getsockname()[0]
	except ConnectionRefusedError:
		ip = '127.0.0.1'
	finally:
		s.close()
	return ip


class LdapConnector:
	def __init__(self, host, port=389, use_ssl=False, starttls=False, base_dn="dc=example,dc=com"):
		self.starttls = starttls

		if use_ssl and port == 389:
			port = 636

		if use_ssl or starttls:
			self.tls = Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1_2)
			self.server = Server(host=host, port=port, use_ssl=use_ssl, tls=self.tls)
		else:
			self.server = Server(host=host, port=port, use_ssl=use_ssl)

		self.connection = None
		self.base_dn = base_dn

	def connect(self, user_dn=None, password=None):

		if (user_dn is None) or (password is None):
			self.connection = Connection(self.server, authentication="ANONYMOUS", read_only=True)
		else:
			self.connection = Connection(self.server, user=user_dn, password=password, read_only=True)

		self.connection.bind()

		if self.starttls:
			self.connection.start_tls()

		return self.connection

	def disconnect(self):
		if self.connection is not None:
			self.connection.unbind()

	def get_server(self, server_dn=None, find_ip=True, find_hostname=True):

		entries = []
		if server_dn is not None:
			if not server_dn.endsWith(self.base_dn):
				server_dn = self.base_dn + server_dn
			entries = self.connection.search(server_dn, '(objectClass=gaiaClient)', search_scope="BASE")
		elif find_ip:
			server_ip = get_local_ip()
			entries = self.connection.search(self.base_dn, f'(&(ipHostNumber={server_ip})(objectClass=gaiaClient))')
		elif find_hostname:
			hostname = gethostname()
			entries = self.connection.search(self.base_dn, f'(&(cn={hostname})(objectClass=gaiaClient))')

		if len(entries) != 1:
			return entries
		else:
			return entries[0]


