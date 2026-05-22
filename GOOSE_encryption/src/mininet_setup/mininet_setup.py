#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import  Host
from mininet.node import OVSKernelSwitch #, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time
import subprocess

duration = 10

def set_topology_s2():
    net = Mininet( topo=None,
                   build=False,
                   ipBase='1.0.0.0/8')

    switchType = OVSKernelSwitch

    info( '*** Starting networking devices\n')
    S1 = net.addSwitch('S1', cls=switchType, dpid='1',failMode='standalone')    
    S2 = net.addSwitch('S2', cls=switchType, dpid='2',failMode='standalone')    

    info( '*** Starting hosts \n')
    H1 = net.addHost('H1', cls=Host, ip='1.1.1.1', defaultRoute='1.1.1.2',mac='00:00:00:00:00:01')
    H2 = net.addHost('H2', cls=Host, ip='1.1.1.2', defaultRoute='1.1.1.1',mac='00:00:00:00:00:02')
    
    info( '*** Setting link parameters\n')

    info( '*** Adding links\n')
    net.addLink(H1, S1)
    net.addLink(S1, S2)
    net.addLink(S2, H2)

    info( '*** Starting network\n')
    net.build()

    info( '*** Starting networking devices \n')
    net.get('S1').start([])
    net.get('S2').start([])
    info( '\n')

    info('**Setting flows to prevent duplication of packets ****\n')
    S1.cmd('ovs-ofctl del-flows S1')
    S1.cmd("ovs-ofctl add-flows S1 'in_port=S1-eth1, actions=drop'")
    S2.cmd('ovs-ofctl del-flows S2')
    S2.cmd("ovs-ofctl add-flows S2 'in_port=S2-eth2, actions=drop'")

    encryption_latency_file_path = "../data/mn_data/encryption_latency_log.csv"
    decryption_latency_file_path = "../data/mn_data/decryption_latency_log.csv"
    try:
        with open(encryption_latency_file_path, "w") as f:
            f.truncate(0)
        info("----------sucessfully cleared encrypt log file for experimental setup -----------\n")
    except Exception as e:
        info("************* could not clear encrypt log file *************\n")
    try:
        with open(decryption_latency_file_path, "w") as f:
            f.truncate(0)
        info("----------sucessfully cleared decrypt log file for experimental setup -----------\n")
    except Exception as e:
        info("************* could not clear decrypt log file *************\n")

    info( '*** Preparing custom sgsim scripts \n')
    CLI.do_run_experiment = s2_experiment
    info( '*** Network started *** \n' )
    CLI(net)
    net.stop()

def s2_experiment(self, line):
    net = self.mn   
    info('Starting experiment... \n')

    algorithms = ["zuc_128", "aes_128" , "sm4", "chacha", "salsa"]
    modes = ["full", "fields_cons", "alldata", "full", "none"]

    for alg in algorithms:
        for mode in modes:
            net.get('H2').cmdPrint(
                'xterm -geometry 70x20-35-35 -fa "Monospace" -fs 8 -T "H - Receiver - {} {}" -e "python3 receive_goose.py ; exec bash"&'.format(
                    alg, mode, alg, mode))

            info("=== Running experiment for algorithm: {} in mode {} ===\n".format(alg, mode))
            net.get('S1').cmdPrint("xterm -geometry 70x20+35+35 -fa 'Monospace' -fs 8 -T 'S1 - {} {}' -e 'bash -c \"../../build/switch1 {} {}; exec bash\"'&".format(alg, mode, alg, mode))


            #net.get('S2').cmd("../build/switch2 {} {} &".format(alg, mode))
            net.get('S2').cmdPrint("xterm -geometry 70x20-35+35 -fa 'Monospace' -fs 8 -T 'S2 - {} {}' -e 'bash -c \"../../build/switch2 {} {}; exec bash\"'&".format(alg, mode, alg, mode))

            #net.get('H1').cmd("python3 send_goose.py &")
            net.get('H1').cmdPrint('xterm -geometry 70x20+35-35 -fa "Monospace" -fs 8 -T "H1 - Sending" -e "python3 send_goose.py; bash"&')

            info("--- running ----")
            time.sleep(duration)
            net.get('S1').cmd("pkill -f './switch1 {} {}'".format(alg, mode))
            net.get('S2').cmd("pkill -f './switch2 {} {}'".format(alg, mode))
            net.get('H1').cmd("pkill -f 'python3 send_goose.py'")
            net.get('H2').cmd("pkill -f 'python3 receive_goose.py'")

            info("Experiment completed for {} encrypting in {}\n".format(alg, mode))
            time.sleep(2)

    info("===ALL EXPERIMENTS FINISHED, CHECK CSV FILES FOR DATA===\n")
    subprocess.run(["python3", "../plots/plot_latency.py"])


if __name__ == '__main__':
    setLogLevel( 'info' )
    set_topology_s2()









