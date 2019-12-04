import json
data = \
{
	"operator": "ct",
	"vendor": "runstone",
	"timestamp": "2019-07-01 00:00:01",
	"data": [
		{
			"id": "digui_hebei_0001",
			"province": "130000",
			"city": "130100",
			"address": "石家庄市裕华区长江大道205号",
			"name": "石家庄电信生产中心",
			"x": 114.64383,
			"y": 38.044589,
			"ipv4": "219.148.3.85,219.148.3.87",
			"ipv6": "240e:4c:4009:1::4,240e:4c:4009:1::6",
			"service": "all",
			"status": "enabled",
			"servers": "rs0001,rs0002",
			"range": "衡水,保定",
			"server7706": "219.148.3.83,219.148.3.84"
		}
	]
}
print(data)

#with open('recursion.json','w') as f:
	#json.dump(data, f, sort_keys=True, indent=4, separators=(',', ': '))

with open('recursion.json','r') as f:
	d = json.load(f)
	print(d)
	print(d==data)

root=\
{
	"operator": "ct",
	"vendor": "runstone",
	"timestamp": "2019-07-01 00:00:01",
	"data": [
		{
			"id": "fuben_hebei_0001",
			"province": "130000",
			"city": "130100",
			"address": "石家庄市裕华区长江大道205号",
			"name": "石家庄电信生产中心",
			"x": 114.64383,
			"y": 38.044589,
			"ipv4": "219.148.3.83,219.148.3.84",
			"ipv6": "240e:4c:4009:1::2,240e:4c:4009:1::3",
			"status": "enabled",
			"deploy": "deployed",   
			"servers": "ds0001,ds0002"
		}
	]
}
print(root)
with open('root_copy.json','r') as f1:
	da = json.load(f1)
	print(da)
	print(da==root)
