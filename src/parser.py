
import sys
import json
from itertools import islice
from pprint import pprint


from Pattern import Pattern
from analysis_tools import analyse_php_ast



def print_file(filePath):
	
	try:
		print("\n" + filePath)
		with open(filePath, 'r') as fp:
			ln = 1
			for line in fp:
				print(" {}: {}".format(str(ln).rjust(2), line.strip('\n')))
				ln = ln + 1
			
	except IOError as e:
		print(e)
		#if e.errno == errno.ENOENT:
			#print("No such filePath or directory: %s" % e)
		#else:
			#print(e)



def get_patterns(filePath):
	
	try:
		print("\n<- importing vulnerability patterns from '" + filePath + "'")
		with open(filePath, 'r') as fp:
			patterns = []
			
			while True:
				# read 5 lines from file
				block = list(islice(fp, 5))
				
				if block:
					# convert read lines into a list
					block = [x for x in block if x !='\n']
					
					pattern = Pattern(block[0], block[1].split(','), block[2].split(','), block[3].split(','))
					
					patterns.append(pattern)
					
					print(pattern)
					
				else:
					# cannot read 5 more lines
					break
			
			return patterns
			
	except IOError as e:
		print("Could not load patterns.\nMaybe you would like to specify a file with '-p'?")
		print(e)
		sys.exit(1)



def check_file(filePath, patterns = None):
	
	if patterns is None:
		patterns = get_patterns("patterns.txt")
	
	try:
		print("\n-> analysing '" + filePath + "'")
		
		with open(filePath) as fp:
			ast = json.load(fp)
			#pprint(ast)
			
		result = analyse_php_ast(ast, patterns)
		
		print(result)
		
		return result
		
		
	except IOError as e:
		print("Could not analyse file.")
		print(e)









