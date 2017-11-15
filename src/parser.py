
import sys
import json
from itertools import islice
from pprint import pprint

from Pattern import Pattern
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
					
					print(pattern)
					
				else:
					# cannot read 5 more lines
					break
			
			return patterns
			
	except IOError as e:
		print("Could not load patterns.\nMaybe you would like to specify a file with '-p'?")
		print(e)
		sys.exit(1)



def get_functions(ast):
	
	functions = {}
	
	for k, v in ast.iteritems():
		if k == "kind" and v == "call":
			arguments = []
			for arg in ast['arguments']:
				if arg['kind'] == "variable":
					#arguments.append(arg['name'])
					arguments.append(arg)
			
			functions[ast['what']['name']] = arguments
			
			
		elif k == "kind" and v == "echo":
			arguments = []
			for arg in ast['arguments']:
				if arg['kind'] == "variable":
					#arguments.append(arg['name'])
					arguments.append(arg)
			
			functions['echo'] = arguments
			
			
		elif isinstance(v, dict):
			functions.update(get_functions(v))
			
			
		elif isinstance(v, list):
			for node in v:
				functions.update(get_functions(node))
		
	return functions




def path_from_sink_to_entry(ast, sinks = None, patterns = None):
	
	if patterns is None:
		patterns = get_patterns("patterns.txt")
	
	if sinks is None:
		possiblePatterns = set()
		
		functions = get_functions(ast)
		sinks = {}
		
		for pattern in patterns:
			for func, args in functions.iteritems():
				if func in pattern.sensitive_sinks:
					sinks[func] = args
					possiblePatterns.add(pattern)
	
	
	path = []
	
	for func, args in sinks.iteritems():
		path.append(func)
		for arg in args:
			stack = [arg]
			while stack:
				
				print([x['name'] for x in stack])
				
				node = stack.pop()
				if node['kind'] == "variable":
					
					for pattern in patterns:
						if node['name'] in pattern.entry_points:
							path.append(node['name'])
							return path
					
					#print("- " + node['name'])
					assign = find_assign(ast, node['name'])
					
					if assign is not None:
						path.append(node['name'])
						right = assign['right']
						
						if right['kind'] == "call" or right['kind'] == "variable":
							#path.append(assign['right']['name'])
							pass
							
						else:
							for var in get_variables(right):
								if var not in stack:
									stack.append(var)
							
						
					
				elif isinstance(node, dict):
					for k, v in node.iteritems():
						if isinstance(v, dict):
							stack.append(v)
							
						elif isinstance(node, list):
							for n in node:
								stack.append(n)
					
				elif isinstance(node, list):
					for n in node:
						stack.append(n)
	
	return path



def check_file(filePath, patterns = None):
	
	if patterns is None:
		patterns = get_patterns("patterns.txt")
	
	try:
		print(bold("\n-> analysing '" + filePath + "'"))
		
		with open(filePath) as fp:
			ast = json.load(fp)
			#pprint(ast)
			
	except IOError as e:
		print("Could not analyse file.")
		print(e)
		sys.exit(1)
	
	
	possiblePatterns = set()
	
	functions = get_functions(ast)
	sinks = {}
	
	for pattern in patterns:
		for func, args in functions.iteritems():
			if func in pattern.sensitive_sinks:
				sinks[func] = args
				possiblePatterns.add(pattern)
	
	
	#FIXME find path of assignments from sink to variable
	path = path_from_sink_to_entry(ast, sinks, patterns)
	print(italic("path: " + str(path)))
	
	newPatterns = []
	for pattern in possiblePatterns:
		for var in path:
			if var in pattern.entry_points:
				newPatterns.append(pattern)
	
	possiblePatterns = newPatterns
	
	result = ""
	
	for element in path:
		for pattern in possiblePatterns:
			if element not in pattern.escapes:
				
				result += "\nVulnerability: " + pattern.name \
						+ "\nEntry point: " + path[-1] \
						+ "\nSanitization: None" \
						+ "\nSensitive Sink: " + path[0] \
						+ "\n"
				
				#FIXME return all matching
				return red(result)
				
	if result == "":
		result = green("Vulnerability: None")
	
	return red(str(result))








