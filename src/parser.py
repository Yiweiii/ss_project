
import sys
import json
from itertools import islice
from pprint import pprint

from Pattern import Pattern
from getters import *
from extras import *



def get_patterns(filePath):
	
	try:
		print(bold("\n<- importing vulnerability patterns from '" + filePath + "'"))
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
					
					#print(pattern)
					
				else:
					# cannot read 5 more lines
					break
			
			return patterns
			
	except IOError as e:
		print("Could not load patterns.\nMaybe you would like to specify a file with '-p'?")
		print(e)
		sys.exit(1)





	#print(blue(str(path)))
	#for x in stack:
		#print(">> "+str(x)+" <<")
	#print("")
	
	
def path_from_sink_to_entry(ast, node = None, patterns = None):
	
	print(blue(">>> " + str(node) + " <<<\n"))

	
	if patterns is None:
		patterns = get_patterns("patterns.txt")
	
	if node is None:
		node = ast
	
	
	if node['kind'] == "call":
		
		print(purple("F -- " + node['what']['name'] + " --\n"))
		# check if function is a sanitization function
		for pattern in patterns:
			if node['what']['name'] in pattern.escapes:
				print(green("ESC -- " + node['what']['name'] + " --\n"))
				return None
		
		for arg in node['arguments']:
			path = path_from_sink_to_entry(ast, arg, patterns)
			print(cyan("F -- " + str(path) + " --\n"))
			if path is not None:
				return path.append(node['what']['name'])
		
		
	elif node['kind'] == "variable":
		print(yellow("VAR -- " + node['name'] + " --\n"))
		
		# check if variable is an entry point
		for pattern in patterns:
			if node['name'] in pattern.entry_points:
				print(yellow("E -- " + node['name'] + " --\n"))
				return [node['name']]
		
		assign = get_assign(ast, node['name'])
		
		if assign is not None:
			path = path_from_sink_to_entry(ast, assign['right'], patterns)
			
			if path is not None:
				print(cyan("A -- " + str(path) + " --\n"))
				return path.append(node['name'])
			else:
				return None
		
	elif node['kind'] == "if":
		print(red("FIXME: function calls not implemented"))			
		
		
	elif node['kind'] == "while":
		print(red("FIXME: function calls not implemented"))
		
		
	else:
		nodesOfInterest = get_calls(node) + get_variables(node)
		for x in nodesOfInterest:
			print(red("R -- " + str(x) + " --"))
		print("")
		
		for n in nodesOfInterest:
			path = path_from_sink_to_entry(ast, n, patterns)
			if path is not None:
				print(cyan("R -- " + str(path) + " --\n"))
				return path
	
	
	return None



def check_file(filePath, patterns = None):
	
	if patterns is None:
		patterns = get_patterns("patterns.txt")
	
	
	# import .json AST to python structures (dicts and lists)
	try:
		print(bold("\n-> analysing '" + filePath + "'"))
		with open(filePath) as fp:
			ast = json.load(fp)
			#pprint(ast)
			
	except IOError as e:
		print("Could not analyse file.")
		print(e)
		sys.exit(1)
	
	
	# find sensitive sinks and delete unmatched patterns
	functions = get_calls(ast)
	sinks = []
	newPatterns = set()
	for pattern in patterns:
		for func in functions:
			if func['what']['name'] in pattern.sensitive_sinks:
				sinks.append(func)
				newPatterns.add(pattern)
				
	patterns = newPatterns
	
	# find path from sinks to a possible entry point
	for sink in sinks:
		path = path_from_sink_to_entry(ast, sink, patterns)
		if path:
			print(italic(cyan("path: " + str(path))))
			break
	
	
	# compute the result
	
	if path is None:
		result = green("Vulnerability: None")
		
	else:
		result = ""
		for element in path:
			for pattern in patterns:
				if element not in pattern.escapes:
					
					result += "\nVulnerability: " + pattern.name \
							+ "\nEntry point: " + path[-1] \
							+ "\nSanitization: None" \
							+ "\nSensitive Sink: " + path[0] \
							+ "\n"
					
					#FIXME return all matching
					return red(result)
	
	
	return result








