
import sys
import json
from itertools import islice
from pprint import pprint

from Pattern import Pattern
from getters import *
from extras import *



def id_nodes(ast):
	id = 0
	stack = [ast]
	
	while stack:
		node = stack.pop()
		node['id'] = id
		id += 1
		
		for k, v in node.iteritems():
			if isinstance(v, dict):
				stack.append(v)
				
			elif isinstance(v, list):
				for n in v:
					stack.append(n)
	
	return ast



# returns a list of vulnerability patterns
def get_patterns(filePath, display = False):
	
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
					
					if display:
						print(pattern)
					
				else:
					# cannot read 5 more lines
					break
			
			return patterns
			
	except IOError as e:
		print("Could not load patterns.\nMaybe you would like to specify a file with '-p'?")
		print(e)
		sys.exit(1)



# returns the path from a node (idealy a function node) to an unsanitized input
# if one does not exist, returns null (None)
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
		#TODO maybe add more functions like echo
		for arg in node['expressions']:
			path = path_from_sink_to_entry(ast, arg, patterns)
			if path is not None:
				path.append(node['kind'])
				return path
		
		
	elif node['kind'] == "offsetlookup":
		
		# check if variable is an entry point
		for pattern in patterns:
			if node['what']['name'] in pattern.entry_points:
				entry = node['what']['name'] + "['" + node['offset']['value'] + "']"
				
				return [entry]
		
		
	elif node['kind'] == "variable":
		assign = get_assignment(ast, node)
		if assign is not None:
			path = path_from_sink_to_entry(ast, assign['right'], patterns)
			
			if path is not None:
				path.append(node['name'])
				return path
		
		
	elif node['kind'] == "if":
		print(red("if blocks are not read here"))
		
		
	elif node['kind'] == "while":
		print(red("while blocks are not read here"))
		
		
	else:
		nodesOfInterest = get_calls(node) + get_variables(node)
		for n in nodesOfInterest:
			path = path_from_sink_to_entry(ast, n, patterns)
			if path is not None:
				return path
	
	
	# default return null
	return None



def check_file(filePath, patterns = None, displayPath = True):
	
	if patterns is None:
		patterns = get_patterns("patterns.txt")
	
	
	# import .json AST to python structures (dicts and lists)
	try:
		print(bold("\n-> analysing '" + filePath + "'"))
		with open(filePath) as fp:
			ast = json.load(fp)
			
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
				if func['kind'] == "call":
					name = func['what']['name']
				else:
					name = func['kind']
					
				if name in pattern.sensitive_sinks:
					sinks.append(func)
					newPatterns.add(pattern)
				
	patterns = list(newPatterns)
	
	
	# id the AST nodes to distinguish x=x assignments
	ast = id_nodes(ast)	
	path = None
	
	# find path from sinks to a possible entry point
	for sink in sinks:
		path = path_from_sink_to_entry(ast, sink, patterns)
		if path is not None:
			break
	
	
	# compute the result
	if path is None:
		result = green("Vulnerability: None\n")
		
	else:
		result = ""
		for element in path:
			for pattern in patterns:
				if element not in pattern.escapes:
					
					result += red("Vulnerability:\t") + pattern.name \
							+ red("\nEntry point:\t") + path[0] \
							+ red("\nSensitive Sink:\t") + path[-1]
						
					if displayPath:
						result += red("\npath: ") + italic(str(path)) + "\n"			
						#result += red("\npath:\n")						
						#for n in path:
							#result += italic(n + "\n")
					else:
						result += "\n"
					
					#TODO maybe return all matching
					return result
	
	return result


