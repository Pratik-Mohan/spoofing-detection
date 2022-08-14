import scapy.all as scapy
import sys
import numpy as np
import matplotlib.pyplot as plt

def getReferenceMACandIPs():
    fl = open("./Logic/packets/IPandMACReference.txt", "r")
    IPs = []
    MACs = []
    for line in fl:
        stripped_line = line.strip()
        strippedList = line.split(' ')
        IPs.append(strippedList[0])
        MACs.append(strippedList[1])
    return IPs, MACs

def getCurrentMACandIPs():
    fl = open("./Logic/packets/IPandMACSpoofed.txt", "r")
    IPs = []
    MACs = []
    for line in fl:
        stripped_line = line.strip()
        strippedList = line.split(' ')
        IPs.append(strippedList[0])
        MACs.append(strippedList[1])
    return IPs, MACs

def doTablePlot(x,y, title, val):
    val1 = ["IP Address", "MAC Address"] 
    val2 = [("Host #"+ str(i+1)) for i in range(5)]
    listofLists = []
    for i in range(5):
        element = []
        element.append(x[i])
        element.append(y[i].strip("\n"))
        listofLists.extend([element])
        print(element)
    val3 = listofLists
    fig, ax = plt.subplots() 

    rcolors = plt.cm.BuPu(np.full(5, 0.1))
    ccolors = plt.cm.BuPu(np.full(2, 0.1))

    elementColors = []
    for index in range(5):
        if val == index:
            elementColors.append(["#800000", "#800000"])
        else:
            elementColors.append(["#006400", "#006400"])

    table = ax.table( 
        cellText = val3,  
        rowLabels = val2,  
        colLabels = val1, 
        cellLoc ='center',
        cellColours=elementColors,
        colColours=ccolors,
        rowColours=rcolors,  
        loc ='upper left')
            
    ax.set_title(title, fontweight ="bold") 
    ax.set_axis_off() 
    plt.show() 

def arpCheck():
    #pinging the the IP we want to check
    #getReferanceMacandIP and getCurrentMACandIP parses through data packets 
    #in form of .txt files (txt for faster execution)
    refIP, refMAC = getReferenceMACandIPs()
    IP, MAC = getCurrentMACandIPs()
    declared = 0
    print("\n")
    for ipAddress in IP:
        if ipAddress in refIP:
            index = refIP.index(ipAddress)
            if(MAC[index] == refMAC[index]):
                print("IP "+ ipAddress +" has reference MAC " + refMAC[index] + "\n")
            else:
                declared = index
                print("IP "+ ipAddress +" has MAC "+ MAC[index] +" which is different from ref MAC "+refMAC[index]+"\n")
    #the loop compares original/planned mac and ip of clients with that of the recieved data packets 
    #to determine presence of an attack and the data is finally plotted  
    doTablePlot(refIP,refMAC, "Hosts Information / No MAC Spoofing", -1)
    doTablePlot(IP,MAC, "Hosts Information / With MAC Spoofing", declared)
