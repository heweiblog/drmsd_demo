

def rank(top):
	
	vals = list(top.values())
	print(vals)
	vals.sort(reverse = True)
	print(vals)

	if len(vals) > 10:
		vals = vals[:10]
	
	print(vals)

	# 去重
	new_vals = []
	for i in vals:
		if i not in new_vals:
			new_vals.append(i)
	
	print(new_vals)

	top10 = []
	for val in new_vals:
		k = [k for k, v in top.items() if v == val]
		#print(k)
		for s in k:
			top10.append({'name':s,'count':val})
	print(top10)


top1 = {'a':22, 'b':33, 'c':44, 'd':55, 'e':33, 'f':55, 'g':13, 'h':1, 'i':2, 'j':3, 'k':5, 'l':0, 'm':0, 'root_copy':0}
top2 = {'a':1, 'b':2, 'c':8, 'd':5, 'e':5, 'f':4}
rank(top1)

print(top1)
