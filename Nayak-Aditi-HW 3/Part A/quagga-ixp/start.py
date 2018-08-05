#!/usr/bin/python

"""
Example network of Quagga routers
(QuaggaTopo + QuaggaService)
"""

import sys
import atexit

# patch isShellBuiltin
import mininet.util
import mininext.util
mininet.util.isShellBuiltin = mininext.util.isShellBuiltin
sys.modules['mininet.util'] = mininet.util

from mininet.util import dumpNodeConnections
from mininet.node import OVSController
from mininet.log import setLogLevel, info

from mininext.cli import CLI
from mininext.net import MiniNExT

from topo import QuaggaTopo

net = None


def startNetwork():
    "instantiates a topo, then starts the network and prints debug information"

    info('** Creating Quagga network topology\n')
    topo = QuaggaTopo()

    info('** Starting the network\n')
    global net
    net = MiniNExT(topo, controller=OVSController)
    net.start()

    info('** Dumping host connections\n')
    dumpNodeConnections(net.hosts)
    
    net.get("r1").cmd("sysctl net.ipv4.ip_forward=1")
    net.get("r2").cmd("sysctl net.ipv4.ip_forward=1")
    net.get("r3").cmd("sysctl net.ipv4.ip_forward=1")
    net.get("r4").cmd("sysctl net.ipv4.ip_forward=1")
    net.get("r4").cmd("sysctl net.ipv4.ip_forward=1")
    net.get("h1").cmd("sysctl net.ipv4.ip_forward=1") 
    net.get("h2").cmd("sysctl net.ipv4.ip_forward=1")
    
    net.get("r1").cmd("ifconfig r1-eth1 193.0.1.1") 
    net.get("r1").cmd("ifconfig r1-eth2 194.0.1.1")
    net.get("r2").cmd("ifconfig r2-eth1 193.0.1.2") 
    net.get("r3").cmd("ifconfig r3-eth1 194.0.1.2")
    net.get("r4").cmd("ifconfig r4-eth1 195.0.1.2")
    net.get("r4").cmd("ifconfig r4-eth2 196.0.1.2")
    
    net.get("h1").cmd("route add default gw 192.0.1.2")
    net.get("h2").cmd("route add default gw 197.1.1.2")
    net.get("r1").cmd("ip route add 197.1.1.0/24 via 193.0.1.2")
    net.get("r1").cmd("ip route add 195.0.1.0/24 via 193.0.1.2")
    net.get("r2").cmd("ip route add 197.1.1.0/24 via 195.0.1.2")
    net.get("r4").cmd("ip route add 193.0.1.0/24 via 195.0.1.1")
    net.get("r4").cmd("ip route add 192.0.1.0/24 via 195.0.1.1")
    net.get("r2").cmd("ip route add 192.0.1.0/24 via 193.0.1.1")
   
    net.get("r1").cmd("ip route add 196.0.1.0/24 via 194.0.1.2")
    net.get("r3").cmd("ip route add 197.1.1.0/24 via 196.0.1.2")
    net.get("r4").cmd("ip route add 194.0.1.0/24 via 196.0.1.1")
    net.get("r3").cmd("ip route add 192.0.1.0/24 via 194.0.1.1")

    net.get("r3").cmd("ip route add 195.0.1.0/24 via 196.0.1.2")
    net.get("r2").cmd("ip route add 194.0.1.0/24 via 193.0.1.1")
    net.get("r3").cmd("ip route add 193.0.1.0/24 via 194.0.1.1")
    net.get("r2").cmd("ip route add 196.0.1.0/24 via 195.0.1.2")

    info('** Testing network connectivity\n')
    net.ping(net.hosts)

    info('** Dumping host processes\n')

    for host in net.hosts:
        host.cmdPrint("ps aux")

    info('** Running CLI\n')
    CLI(net)


def stopNetwork():
    "stops a network (only called on a forced cleanup)"

    if net is not None:
        info('** Tearing down Quagga network\n')
        net.stop()

if __name__ == '__main__':
    # Force cleanup on exit by registering a cleanup function
    atexit.register(stopNetwork)

    # Tell mininet to print useful information
    setLogLevel('info')
    startNetwork()
