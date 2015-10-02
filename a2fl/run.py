#!/usr/bin/env python2.7

from __future__   import print_function
from argparse     import ArgumentParser
from subprocess   import Popen, STDOUT, PIPE
from socket       import socket, AF_INET, SOCK_STREAM
from time         import sleep
import os
from sys          import stdout
from threading    import Thread;
from mininet.net  import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController
from mininet.node import OVSKernelSwitch

MAGIC_MAC = "00:11:00:11:00:11"
MAGIC_IP  = "10.111.111.111"

class MyTopo(Topo):
	"""Simple topology example."""

	def __init__(self):
		"""Create custom topo."""

		# Initialize topology
		Topo.__init__(self)

		# EDIT HERE
		

class Ryu(Thread):

	def __init__(self,  log=None):

		Thread.__init__(self)
		self.log = log
		print("Initializing Ryu controller and logs "+log)

	def run(self):
		home = os.getenv("HOME")
 		os.chdir(home + "/ryu")
		os.environ["PYTHONPATH"] = "."
		if self.log != None:
			self.log = open(self.log, 'w')

		self.proc = Popen(
			("./bin/ryu-manager","--verbose","ryu/app/simple_switch.py"),
			stdout=self.log, stderr=self.log
		)

class Prox(Thread):

	def __init__(self, node, log=None):

		Thread.__init__(self)
		self.node = node
		self.log  = log

	def run(self):

		if self.log != None:
			self.log = open(self.log, 'w')

		while True:
			self.proc = self.node.popen(
				["./ptprox", "prox-eth0"],
				stdout=self.log, stderr=self.log
			)
			self.proc.wait()


def parse_args():

	parser = ArgumentParser()
	parser.add_argument("-l", "--log",   help="ryu log file",    default="ryu.log")
	parser.add_argument("-p", "--prox",  help="path to ptprox.c",       default="ptprox.c")
	parser.add_argument("-m", "--plog",  help="ptprox log file",        default="ptprox.log")
	args = parser.parse_args()
	return args

def wait_on_controller():

	s = socket(AF_INET, SOCK_STREAM)
	addr = ("localhost", 6633)

	try:
		s.connect(addr)
		s.close()
		return
	except:
		pass

	print("Waiting on controller", end=""); stdout.flush()

	while True:
		sleep(1)
		try:
			s.connect(addr)
			s.close()
			print("")
			return
		except:
			print(".", end=""); stdout.flush()
			continue

def build_prox(psrc):

	gcc_proc = Popen(stdout=PIPE, stderr=STDOUT,
			args=("gcc", psrc, "-o", "ptprox", "-l", "pcap")
	)

	r = gcc_proc.wait()
	if r != 0:
		out, _ = gcc_proc.communicate()
		print(out)
		exit(1)

if __name__ == "__main__":

	args = parse_args()

	fl = Ryu(args.log)
	fl.start()

	build_prox(args.prox)
	wait_on_controller()

	mn = Mininet(
		topo=MyTopo(),
		autoSetMacs=True,
		autoStaticArp=True,
		controller=RemoteController,
		switch=OVSKernelSwitch
	)

	mn.start()

	sleep(10) # yuk
	for src in mn.hosts:
		for dst in mn.hosts:
			if src != dst:
				# This is to work around a bug in the version of mininet on the VM
				src.setARP(ip=dst.IP(), mac=dst.intf(None).MAC())
		# Magic for floodlight to map MAC addresses to switch ports
		print("Magic ping " + src.intf(None).MAC())
		src.setARP(ip=MAGIC_IP, mac=MAGIC_MAC)
		src.cmd("ping", "-c1", "-W1", MAGIC_IP)

	px = Prox(mn.getNodeByName("prox"), args.plog)
	px.start()
	mn.interact()

	# TODO cleanup threads

# vim: set noet ts=4 sw=4 :
