from Logic.packets import txtPacket as txtP
import settings
from Logic.SNaSSInitialize import plot, calculatePercentages, sequenceNumberWarning


def spoofDetection(packet):
    (sa, sn, ss) = txtP.extractPacket(packet)
    if sa in settings.clients:
        #since the sequence number loops after 4092 counts in TCP comm so we check likewise to avoid step jumps
        if sn < 4093:
            seqgap = abs(sn - settings.clients[sa]["seqNum"][-1])
        else:
            seqgap = abs(-(4096 - (sn - settings.clients[sa]["seqNum"][-1])))
        siggap = abs(ss - settings.clients[sa]["sigStr"][-1])
        settings.clients[sa]["seqNum"].append(sn)
        settings.clients[sa]["sigStr"].append(ss)
        settings.clients[sa]["seqGap"].append(seqgap)
        settings.clients[sa]["sigGap"].append(siggap)
        settings.clients[sa]["seqPer"] = calculatePercentages(
            settings.clients[sa]["seqGap"])
        settings.clients[sa]["sigPer"] = calculatePercentages(
            settings.clients[sa]["sigGap"])
        settings.clients[sa]["warning"] += ((len(settings.clients[sa]["seqNum"])-1)*sequenceNumberWarning(
            settings.clients[sa], seqgap, sn, len(settings.clients[sa]["seqNum"])-1))/len(settings.clients[sa]["seqNum"])
        settings.clients[sa]["warning"] = (((len(settings.clients[sa]["seqNum"])-1)*settings.clients[sa]["warning"]+10)/(len(settings.clients[sa]["seqNum"]))
                                           ) if siggap > 5 else (((len(settings.clients[sa]["seqNum"])-1)*settings.clients[sa]["warning"]-1)/(len(settings.clients[sa]["seqNum"])))
        if settings.clients[sa]["warning"] > -0.2 and (len(settings.clients[sa]["seqNum"])) > 100:
            print(sa + "is most definetely a spoofed mac address")
            decision = input("Plot figure? (y yes, n no)").lower()
            if decision == "y":
                plot(settings.clients[sa], sa)
        elif settings.clients[sa]["warning"] > -1 and (len(settings.clients[sa]["seqNum"])) > 100:
            print(sa + "might be a spoofed mac address")
            decision = input("Plot figure? (y yes, n no)").lower()
            if decision == "y":
                plot(settings.clients[sa], sa)
    else:
        settings.clients[sa] = {}
        settings.clients[sa]["seqNum"] = [sn]
        settings.clients[sa]["sigStr"] = [ss]
        settings.clients[sa]["seqGap"] = []
        settings.clients[sa]["sigGap"] = []
        settings.clients[sa]["warning"] = 0
