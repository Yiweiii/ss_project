
import sys
import json
from itertools import islice
from pprint import pprint

from Pattern import Pattern



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




def get_variables(ast):
	
	variables = {}
	
	for k, v in ast.iteritems():
		#if isinstance(v, dict):
				#variables.update(get_variables(v))
			
		#elif isinstance(v, list):
			#for node in v:
				#variables.update(get_variables(node))
				
		#else:
			#if k == "kind" and v == "variable":
				#variables[ast['name']] = False
				
				
		if k == "kind" and v == "variable":
			variables[ast['name']] = False
		elif isinstance(v, dict):
				variables.update(get_variables(v))
			
		else:
			if isinstance(v, list):
				for node in v:
					variables.update(get_variables(node))
				
		
	return variables


def get_sensitive_sinks(ast):
	
	sensitiveSinks = {}
	
	for k, v in ast.iteritems():
		if isinstance(v, dict):
				variables.update(get_variables(v))
			
		elif isinstance(v, list):
			for node in v:
				variables.update(get_variables(node))
				
		else:
			if k == "kind" and v == "call":
				variables[ast['name']] = False
	
	return sensitiveSinks



def check_file(filePath, patterns = None):
	
	if patterns is None:
		patterns = get_patterns("patterns.txt")
	
	try:
		print("\n-> analysing '" + filePath + "'")
		
		with open(filePath) as fp:
			ast = json.load(fp)
			#pprint(ast)
			
	except IOError as e:
		print("Could not analyse file.")
		print(e)
		sys.exit(1)
		
		
	variables = get_variables(ast)
	possiblePatterns = []
	
	result = {
		"Vulnerability": None,
		"Entry point": None,
		"Sanitization": None,
		"Sensitive Sinks": None
		}
	
	for pattern in patterns:
		for k, v in variables.iteritems():
			if k in pattern.entry_points:
				variables[k] = True
				possiblePatterns.append(pattern)
			
	print("Program variables " + str(variables))
	print("Possible patterns of vulnerability: " + str(possiblePatterns))
	
	
	#FIXME find path from variable to sink
	
	#FIXME check if sanitization function in that path
	
	return result
		
		










