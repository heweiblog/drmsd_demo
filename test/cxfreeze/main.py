#!/usr/bin/python3
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os, time, daemon, multiprocessing
from log import logger
import conf
from upload import upload_task
from server import main_task

from daemon import Daemon

class pantalaimon(Daemon):
	def run(self):
		logger.info('{} main start at {}'.format(os.getpid(),time.ctime()))
		logger.info(conf.conf)
		print(conf.conf)

		p = multiprocessing.Process(target = main_task, args = ())
		p1 = multiprocessing.Process(target = upload_task, args = ())
		p.start()
		p1.start()
		p.join()
		p1.join()

if __name__ == '__main__':
	pineMarten = pantalaimon('/tmp/main.pid')
	pineMarten.start()

'''
#if __name__ == '__main__':
#with daemon.DaemonContext():
	logger.info('{} main start at {}'.format(os.getpid(),time.ctime()))
	logger.info(conf.conf)
	print(conf.conf)

	p = multiprocessing.Process(target = main_task, args = ())
	p1 = multiprocessing.Process(target = upload_task, args = ())
	p.start()
	p1.start()
	p.join()
	p1.join()

	logger.info('main process end at: %s' % time.ctime())
'''
