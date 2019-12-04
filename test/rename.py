from time import sleep
import daemon,os

with daemon.DaemonContext():
	while True:
		if os.path.exists('/home/heweiwei/drms/test/1.txt'):
			os.rename('/home/heweiwei/drms/test/1.txt','/home/heweiwei/drms/test/2.txt')
		sleep(1)
