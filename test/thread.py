from time import sleep
import threading, os, multiprocessing

def test():
	i = 1
	while True:
		sleep(1)
		l = os.listdir('/var/drmsd_waj')
		print(i,l)
		i+=2


def main():
	threading._start_new_thread(test,())
	i = 0
	while True:
		sleep(1)
		i+=2
		print(i)

p2 = multiprocessing.Process(target = main, args = ())
p2.start()
p2.join()
