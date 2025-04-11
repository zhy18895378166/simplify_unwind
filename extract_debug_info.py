import re

with open("debug_info.txt", 'r') as f:
	txt = f.read()
	sep = 'Compilation Unit'
	pattern = re.compile(r'(%s.*?)(?=%s|$)' %(sep, sep), re.DOTALL)
	result = pattern.findall(txt)
	print(result)
