
import sys
from os import listdir
from os.path import isfile, join

from parser import *



def help():
	print("\n" + "-"*90)
	
	print("usage:")
	print("\tpython main.py [options]")
	
	print("\noptions:")
	#print("\t-a\t analyse all slices")
	print("\t-f\t specify file")
	print("\t-i\t interactive shell")
	print("\t-d\t draw code graph")
	print("\t-h\t help")
	
	print("-"*90)
	
	
	
def print_numbered_list(list):
	for t in range(len(list)):
		print("  " + str(t).rjust(2) + "  " + list[t])



def get_available_files(filesDirectory):
	
	return [filesDirectory+f for f in listdir(filesDirectory) if isfile(join(filesDirectory, f))]



def main():
	
	flags = {}
	slicesDir = "slices/"
	
	n = 1
	for arg in sys.argv[1:]:
		
		if "-h" in sys.argv:
			help()
			sys.exit(0)
			
		elif arg == "-f":
			flags["-f"] = argv[n+1]			
			
		elif arg == "-d":
			flags["-d"] = True
			
		elif arg == "-i":
			flags["-i"] = True
			
		elif arg.startswith("-"):
			print("unrecognised flag '" + arg + "'.")
		
		n = n + 1
	
	
	for f in get_available_files(slicesDir):
		check_file(f)
	
	
	print("\nDone.\n")
	
	
	
if __name__ == '__main__':
	main()
	
