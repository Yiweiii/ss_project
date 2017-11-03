

def check_file(file):
	
	print("\n" + file)
	with open(file, 'r') as fp:
		ln = 1
		for line in fp:
			print("  {}: {}".format(ln, line.strip()))
			ln = ln +1
		
		
		
	#fp = open(file, 'r')
	#ln = 1
	#line = fp.readline()
	#while line:
		#print("\tLine {}: {}".format(ln, line.strip()))
		#line = fp.readline()
		#ln += 1
	#fp.close()
	
	