from time import sleep
import daemon,os

with daemon.DaemonContext():
	i = 1
	while True:
		with open('/home/heweiwei/drms/test/1.txt','w') as f:
			while True:
				if i%30 == 0:
					f.write('write num {}\n'.format(i))
					i += 1
					break
				f.write('write num {}\n'.format(i))
				i += 1
				sleep(1)

