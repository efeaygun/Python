from scapy.all import ARP, Ether, srp, conf
import netifaces
import ipaddress

try:
	def get_active_interface_info():
		#Aktif varsayılan ağ geçidi üzerinden intarface ismini al
		default_iface = conf.route.route("0.0.0.0")[0]

		#Interface bilgilerinden IP ve Subnet bilgilerini al
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

	cidr = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
	target_ip = str(cidr)

	arp = ARP(pdst=target_ip)


	ether = Ether(dst="ff:ff:ff:ff:ff:ff")

	packet = ether/arp


	result = srp(packet, timeout=3, verbose=0)[0]


	clients = []

	for sent, received in result:
		clients.append({'ip': received.psrc, 'mac': received.hwsrc})

	print(f"Iface: {iface}")
	print("Available devices in the network:")
	print("IP" + " "*22+"MAC")
	for client in clients:
		print("{:16}	{}".format(client['ip'], client['mac']))
except Exception as error:
	print("Some wrong found", error)