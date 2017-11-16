
import sys
import json
from itertools import islice
from pprint import pprint

from Pattern import Pattern
from extras import *
from getters import *



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




def path_from_sink_to_entry(ast, sink, patterns = None):
	
	if patterns is None:
		patterns = get_patterns("patterns.txt")
	
	
	functions = get_calls(ast)
	sinks = []
	
	# find sensitive sinks and delete unmatched patterns
	newPatterns = set()
	for pattern in patterns:
		for func in functions:
			if func['what']['name'] in pattern.sensitive_sinks:
				sinks.append(func)
				newPatterns.add(pattern)
				
	patterns = newPatterns
	
	
	path = [sink['what']['name']]
	
	#for arg in sink['arguments']:
	
	stack = list(sink['arguments'])
	visited = []
	
	while stack:
		
		print(blue(str(path)))
		for x in stack:
			print(">> "+str(x)+" <<")
		print("")
		
		node = stack.pop()
		if node['kind'] == "variable":
			
			for pattern in patterns:
				if node['name'] in pattern.entry_points:
					path.append(node['name'])
					return path
			
			assign = find_assign(ast, node['name'])
			
			if assign is not None and assign not in visited:
				visited.append(assign)
				path.append(node['name'])
				stack.append(assign['right'])
				#path.append(node['name'])
				#right = assign['right']
				
				#if right['kind'] == "call" or right['kind'] == "variable":
					##path.append(assign['right']['name'])
					#pass
					
				#else:
					#for var in get_variables(right):
						#if var not in stack:
							#stack.append(var)
			
		elif node['kind'] == "call":
			print(red("FIXME: function calls not implemented"))
			
			path.append(node['what']['name'])
			
			# check if sanitization function
			for pattern in patterns:
				if node['what']['name'] in pattern.escapes:
					continue
			
			for arg in node['arguments']:
				if arg['kind'] == "variable" or arg['kind'] == "call":
					#arguments.append(arg['name'])
					stack.append(arg)
			
			
		elif node['kind'] == "if":
			print(red("FIXME: function calls not implemented"))			
			
		elif node['kind'] == "while":
			print(red("FIXME: function calls not implemented"))
			
		#elif node['kind'] == "encapsed":
		else:
			stack = stack + get_calls(node) + get_variables(node)
			
			#functions = get_calls(node)
			#variables = get_variables(node)
			#if functions:
				#for func in functions:
					#if func not in stack:
						#stack.append(func)
				
			#else:
				#for var in get_variables(node):
					#if var not in stack:
						#stack.append(var)
			
		#elif isinstance(node, dict):
			#for k, v in node.iteritems():
				#if isinstance(v, dict):
					#stack.append(v)
					
				#elif isinstance(node, list):
					#for n in node:
						#stack.append(n)
			
		#elif isinstance(node, list):
			#for n in node:
				#stack.append(n)

	return path



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
				
	if result == "":
		result = green("Vulnerability: None")
	
	return result








