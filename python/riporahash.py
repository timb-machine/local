import re
datafile = open("SYSTEM01.dbf","rb")
datafile.seek(448767,0)
data = datafile.read(6553500)


results = re.findall(r"[0-9A-Z_.-]+\x02\xc1\x02\x10[0-9A-F]{16}",data)

for result in results:
                username,password = result.split("\x02\xc1\x02\x10")
                print "{0}:{1}".format(username,password)
