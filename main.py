from Logic import arpReq
from Logic import SNaSSInitialize
import settings

arpReq.arpCheck()

SNaSSInitialize.initialize('./Logic/packets/SniffedPackets.txt')
for sa in settings.clients:
    SNaSSInitialize.plot(settings.clients[sa], sa)
    break

SNaSSInitialize.initialize('./Logic/packets/SniffedPacketsSpoofed.txt')
for sa in settings.clients:
    if settings.clients[sa]["warning"] > -0.2 and (len(settings.clients[sa]["seqNum"])) > 100:
        print(sa + "is most definetely a spoofed mac address")
        decision = input("Plot figure? (y yes, n no)").lower()
        if decision == "y":
            SNaSSInitialize.plot(settings.clients[sa], sa)
    elif settings.clients[sa]["warning"] > -1 and (len(settings.clients[sa]["seqNum"])) > 100:
        print(sa + " might be a spoofed mac address")
        decision = input("Plot figure? (y yes, n no)").lower()
        if decision == "y":
            SNaSSInitialize.plot(settings.clients[sa], sa)
