import sys
import json
from itertools import islice
from pprint import pprint

from Vulnerable import Vulnerable
from getters import *


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
def get_patterns(file_dir, display = False):
	print("importing vulnerability patterns from" + file_dir)
	with open(file_dir, 'r') as fp:
		patterns = []
		
		while True:
			field = list(islice(fp, 5))
			
			if field:
				field = [x for x in field if x !='\n']		
				pattern = Vulnerable(field[0], field[1].split(','), field[2].split(','), field[3].split(','))
				patterns.append(pattern)
				
			else:
				break
		
		return patterns


def path_from_sink_to_entry(ast, node, patterns):
	
	if node['kind'] == "call":
		
		# check if function is a sanitization function
		for pattern in patterns:
			if node['what']['name'] in pattern.validation_funcs:
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
		print("das")
		print(assign)
		if assign is not None:
			path = path_from_sink_to_entry(ast, assign['right'], patterns)
			
			if path is not None:
				path.append(node['name'])
				return path
		
		
	elif node['kind'] == "if":
		print("no if is implemented")
		
		
	elif node['kind'] == "while":
		print("no while is implemented")
		
		
	else:
		nodesOfInterest = get_functions(node) + get_variables(node)
		for n in nodesOfInterest:
			path = path_from_sink_to_entry(ast, n, patterns)
			if path is not None:
				return path
	
	# default return null
	return None



def check_vulnerability(file_dir, patterns):

	print("analyzing " + file_dir)
	with open(file_dir) as fp:
		ast = json.load(fp)
	
	functions = get_functions(ast)
	sinks = []
	subpatterns = []
	for pattern in patterns:
		for function in functions:
			if function not in sinks:
				if function['kind'] == "call":
					name = function['what']['name']
				else:
					name = function['kind']
					
				if name in pattern.sensitive_sinks:
					sinks.append(function)
					subpatterns.append(pattern)

	# id the AST nodes to distinguish x=x assignments
	ast = id_nodes(ast)	
	path = None
	
	# find path from sinks to a possible entry point
	for sink in sinks:
		# print(sink)
		path = path_from_sink_to_entry(ast, sink, subpatterns)
		if path is not None:
			break
		
	# compute the result
	if path is None:
		result = 'Vulnerability: None\n'
		
	else:
		result = ""
		for element in path:
			for subpattern in subpatterns:
				if element not in subpattern.validation_funcs:
					result += "Vulnerability: " + subpattern.name + "\n" \
							+ "Entry point: " + path[0] + "\n" \
							+ "Sensitive Sink: " + path[-1] + "\n"
					return result

	return result


