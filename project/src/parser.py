

def check_file(file):
	
	try:
		print("\n" + file)
		with open(file, 'r') as fp:
			ln = 1
			for line in fp:
				print(" {}: {}".format(str(ln).rjust(2), line.strip('\n')))
				ln = ln + 1
			
	except IOError as e:
		print(e)
		#if e.errno == errno.ENOENT:
			#print("No such file or directory: %s" % e)
		#else:
			#print(e)



