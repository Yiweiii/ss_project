
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


	
def path_from_sink_to_entry(ast, node = None, patterns = None):
	
	if patterns is None:
		patterns = get_patterns("patterns.txt")
	
	if node is None:
		node = ast
	
	
	if node['kind'] == "call":
		
		# check if function is a sanitization function
		for pattern in patterns:
			if node['what']['name'] in pattern.escapes:
				return None
		
		for arg in node['arguments']:
			path = path_from_sink_to_entry(ast, arg, patterns)
			if path is not None:
				path.append(node['what']['name'])
				return path
		
		
	elif node['kind'] == "echo":
		#FIXME
		print(red("FIXME: echo calls not implemented"))
		
		
	elif node['kind'] == "offsetlookup":
		
		# check if variable is an entry point
		for pattern in patterns:
			if node['what']['name'] in pattern.entry_points:
				entry = node['what']['name'] + "['" + node['offset']['value'] + "']"
				
				return [entry]
		
		
	elif node['kind'] == "variable":
		
		assign = get_assign(ast, node['name'])
		
		if assign is not None:
			path = path_from_sink_to_entry(ast, assign['right'], patterns)
			
			if path is not None:
				path.append(node['name'])
				return path
		
		
	elif node['kind'] == "if":
		#FIXME
		print(red("FIXME: function calls not implemented"))			
		
		
	elif node['kind'] == "while":
		#FIXME
		print(red("FIXME: function calls not implemented"))
		
		
	else:
		nodesOfInterest = get_calls(node) + get_variables(node)
		for n in nodesOfInterest:
			path = path_from_sink_to_entry(ast, n, patterns)
			if path is not None:
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
			if func not in sinks:
				if func['what']['name'] in pattern.sensitive_sinks:
					sinks.append(func)
					newPatterns.add(pattern)
				
	patterns = list(newPatterns)
	
	
	path = None
	
	# find path from sinks to a possible entry point
	for sink in sinks:
		path = path_from_sink_to_entry(ast, sink, patterns)
		print(italic("path: " + str(path)))
		if path is not None:
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








