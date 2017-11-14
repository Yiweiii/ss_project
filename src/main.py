
import sys
from os import listdir
from os.path import isfile, join

from parser import *



def help():	
	print("usage:")
	print("\tpython main.py [options]")
	
	print("\noptions:")
	#print("\t-a\t analyse all slices")
	print("\t-d\t specify slices directory\t (default 'slices/')")
	print("\t-f\t specify code slice file\t (default checks all files)")
	print("\t-p\t specify patterns file\t (default './patterns.txt')")
	print("\t-i\t interactive shell")
	print("\t-g\t draw code graph")
	print("\t-h\t help")
	
	print("\n")



def get_available_files(filesDirectory):
	
	return [f for f in listdir(filesDirectory) if isfile(join(filesDirectory, f))]


	
def print_numbered_list(list):
	for t in range(len(list)):
		print(str(t).rjust(4) + "  " + list[t])
	


def shell(slicesDir):
	
	while True:
		files = get_available_files(slicesDir)
		
		print("\navailable code slices:")
		print_numbered_list(files)
		
		cmd = raw_input("\n-> ").split()
		
		if cmd[0] == "q" or cmd[0] == "quit":
			break
		
		elif cmd[0] == "exit":
			sys.exit(1)
		
		file = files[int(cmd[0])]
		
		check_file(slicesDir + file)



def main():
	
	flags = {"-d": "slices/", "-f": None, "-p": "patterns.txt", "-g": False, "-i": False}
	#slicesDir = "slices/"
	
	n = 1
	for arg in sys.argv[1:]:
		
		if arg == "-h":
			help()
			sys.exit(0)
			
		elif arg == "-f":
			flags["-f"] = sys.argv[n+1]
			
		elif arg == "-d":
			flags["-d"] = sys.argv[n+1]
			
		elif arg == "-p":
			flags["-p"] = sys.argv[n+1]	
			
		elif arg == "-g":
			flags["-g"] = True
			
		elif arg == "-i":
			flags["-i"] = True
			
		elif arg.startswith("-"):
			print("unrecognised flag '" + arg + "'.")
		
		n = n + 1
	
	
	if flags["-f"]:
		check_file(flags["-d"] + flags["-f"])
		
	if flags["-i"]:
		shell(flags["-d"])
		
		
	
	
	if not ( flags["-f"] or flags["-i"] ):
		patterns = get_patterns(flags["-p"])
		
		for f in get_available_files(flags["-d"]):
			
			vulnerabilities = check_file(flags["-d"] + f, patterns)
			
			print(vulnerabilities)
	
	
	print("\nDone.\n")
	
	
	
	
	
if __name__ == '__main__':
	main()
	
