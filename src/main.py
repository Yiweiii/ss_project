import sys
from os import listdir
from os.path import isfile, join

from parser import *

def get_available_files(file_dir):
	return [file for file in listdir(file_dir) if isfile(join(file_dir, file))]


def main():

	patterns = get_patterns("patterns.txt")
	print(patterns)

	for file in get_available_files("slices/"):
		print(check_vulnerability("slices/" + file, patterns))
	
	print("\nDone.\n")
	
	
	
if __name__ == '__main__':
	main()