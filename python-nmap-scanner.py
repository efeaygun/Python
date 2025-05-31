from scapy.all import ARP, Ether, srp, conf
import netifaces
import ipaddress
import nmap

try:
	def get_active_interface_info():
		#Aktif varsayılan ağ geçidi üzerinden interface ismini al
		default_iface = conf.route.route("0.0.0.0")[0]

		#Interface bilgilerinden IP adresini al
		iface_addrs = netifaces.ifaddresses(default_iface)

		#IPv4 bilgilerini çek
		if netifaces.AF_INET in iface_addrs:
			ipv4_info = iface_addrs[netifaces.AF_INET][0]
			ip_address = ipv4_info['addr']
			netmask = ipv4_info['netmask']
			return default_iface, ip_address, netmask
		else:
			return None, None, None

	iface, ip, mask = get_active_interface_info()

	if ip is None or mask is None:
		print("IP bilgisi alınamadı")
		exit()

	#IP/Mask -> CIDR formatına çevir
	target_net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
	target_ip = str(target_net)

	#ARP isteği hazırla
	arp = ARP(pdst=target_ip)
	ether = Ether(dst="ff:ff:ff:ff:ff:ff")
	packet = ether / arp

	#Paketleri gönder al
	result = srp(packet, timeout=3, verbose=0)[0]

	clients = []		

	for sent, received in result:
		clients.append(received.psrc)

	#Nmap ile portları tarama
	scanner = nmap.PortScanner()

	for target in clients:
		print(f"\nScanning {target}...")
		scanner.scan(hosts=target, arguments='-sS -sV -Pn -O')
		if target in scanner.all_hosts():
			print("Host:", target)
			print("State:", scanner[target].state())
			for proto in scanner[target].all_protocols():
				print("Protocol:", proto)
				ports = scanner[target][proto].keys()
				for port in sorted(ports):
					state = scanner[target][proto][port]['state']
					name = scanner[target][proto][port].get('name', '')
					version = scanner[target][proto][port].get('version', '')
					print(f"Port: {port} | State: {state} | Service: {name} {version}")
except Exception as error:
	print("Some wrong found: ", error)
