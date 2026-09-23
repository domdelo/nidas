from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap


packets = []


# --------------------------------------------------
# 1. Normal traffic
# --------------------------------------------------

packets.append(
    IP(src="192.168.1.10", dst="192.168.1.20")
    / TCP(sport=50000, dport=443, flags="S")
)

packets.append(
    IP(src="192.168.1.10", dst="8.8.8.8")
    / UDP(sport=53000, dport=53)
    / DNS(
        rd=1,
        qd=DNSQR(qname="www.example.com")
    )
)


# --------------------------------------------------
# 2. Port scan
# --------------------------------------------------

for i in range(25):

    packet = (
        IP(
            src="192.168.1.50",
            dst="192.168.1.100"
        )
        / TCP(
            sport=40000 + i,
            dport=20 + i,
            flags="S"
        )
    )

    packet.time = 1 + (i * 0.1)

    packets.append(packet)


# --------------------------------------------------
# 3. SYN flood
# --------------------------------------------------

for i in range(120):

    packet = (
        IP(
            src="192.168.1.60",
            dst="192.168.1.110"
        )
        / TCP(
            sport=45000 + i,
            dport=80,
            flags="S"
        )
    )

    packet.time = 10 + (i * 0.05)

    packets.append(packet)


# --------------------------------------------------
# 4. Suspicious DNS query
# --------------------------------------------------

suspicious_query = (
    "a8dk29flm92kx7qp4mnz7q2w9e8r5t6y"
    "u3i4o7p8a1s2d3f4.example.com"
)

dns_packet = (
    IP(
        src="192.168.1.70",
        dst="8.8.8.8"
    )
    / UDP(
        sport=54000,
        dport=53
    )
    / DNS(
        rd=1,
        qd=DNSQR(qname=suspicious_query)
    )
)

dns_packet.time = 30

packets.append(dns_packet)


# --------------------------------------------------
# 5. ICMP tunneling-like traffic
# --------------------------------------------------

for i in range(15):

    packet = (
        IP(
            src="192.168.1.80",
            dst="192.168.1.120"
        )
        / ICMP(
            type=8,
            code=0
        )
        / Raw(
            load=b"A" * 200
        )
    )

    packet.time = 40 + i

    packets.append(packet)


# --------------------------------------------------
# Write PCAP
# --------------------------------------------------

wrpcap(
    "samples/nidas_demo.pcap",
    packets
)

print(
    f"Created samples/nidas_demo.pcap "
    f"with {len(packets)} packets."
)