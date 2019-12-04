import multiprocessing,time,sys

try:
	value = 10
	#share_var = multiprocessing.Manager().Value(10, value)
	share_var = multiprocessing.Value('d', value)
	print(share_var)
except Exception as e:
	print('load conf or create log error:'+str(e))
	sys.exit(1)


def main_task():
	i = 0
	while True:
		time.sleep(1)
		i+=1
		print(i,int(share_var.value))
		if i > 2:
			share_var.value += i
			i = 0

def upload_task():
	while True:
		time.sleep(1)
		print('process2: val=',int(share_var.value))

while True:
	p = multiprocessing.Process(target = main_task, args = ())
	p1 = multiprocessing.Process(target = upload_task, args = ())
	p.start()
	p1.start()
	print(222)
	p.join()
	p1.join()

