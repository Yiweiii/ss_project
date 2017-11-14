
import sys
import json
from itertools import islice
from pprint import pprint

from Pattern import Pattern
from extras import italic, underline, bold, red, green
from extras import find_assign, get_variables, propagate_taint, print_program_check



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
					arguments.append(arg['name'])
			
			functions[ast['what']['name']] = arguments
			
			
		elif k == "kind" and v == "echo":
			arguments = []
			for arg in ast['arguments']:
				if arg['kind'] == "variable":
					arguments.append(arg['name'])
			
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
		for arg in args:
			
			node = arg
			while node:
				print("FIXME") #FIXME
				node = find_assign(ast, node)
				if node:
					right = node['right']
					path.append(right)
	
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
				
	
	#variables = list(get_variables(ast))
	#tainted = dict.fromkeys(variables, False)
	
	#for pattern in patterns:
		#for var in variables:
			#if var in pattern.entry_points:
				#tainted[var] = True
	
	
	##print_program_check(variables, tainted, functions, sinks, possiblePatterns)
	
	#print(green(str(tainted)))
	#propagate_taint(ast, tainted)
	#print(red(str(tainted)))
	
	#FIXME find path of assignments from sink to variable
	path = path_from_sink_to_entry(ast, sinks, patterns)
	print(italic("path: ") + str(path))
	
	result = []
	
	#FIXME check if sanitization function in that path
	for element in path:
		for pattern in patterns:
			if element not in pattern.escapes:
				result.append({
					"Vulnerability": pattern.name,
					"Entry point": path[0],
					"Sanitization": None,
					"Sensitive Sink": path[-1]
					})
	
	if not result:
		result = green(str({ "Vulnerability": None }))
	
	return result








