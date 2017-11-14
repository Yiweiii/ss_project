
class Color:
	PURPLE = '\033[95m'
	BLUE = '\033[94m'
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	RED = '\033[91m'
	END = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	ITALIC = '\x1B[3m'
        
def green(string): return Color.HEADER + string + Color.END
def red(string): return Color.RED + string + Color.END
def yellow(string): return Color.YELLOW + string + Color.END

def italic(string): return Color.ITALIC + string + Color.END
def underline(string): return Color.UNDERLINE + string + Color.END
def bold(string): return Color.BOLD + string + Color.END



def dfs_from_sink_to_var(ast, patterns = None):
	if patterns is None:
		patterns = get_patterns("patterns.txt")
	
	functions = {}
	visited = []
	stack = [ast]
	
	while stack:
		vertex = stack.pop()
		if vertex not in visited:
			visited.add(vertex)
			stack.extend(graph[vertex] - visited)
	return visited

	
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
				
				
				


def print_program_check(variables, tainted, functions, sinks, possiblePatterns):
	
	print(italic("Program variables: ") + str(variables))
	print(italic("Tainted: ") + str(tainted))
	print(italic("Functions: ") + str(functions))
	print(italic("Sinks: ") + str(sinks))
	print(italic(yellow("Possible patterns of vulnerability: ")) + str(possiblePatterns))



def propagate_taint(ast, variables):
	
	# assume we areceive an ast
	for k, v in ast.iteritems():
		if k == u"kind" and v == u"assign":
			
			left = ast['left']
			right = ast['right']
			
			if left['kind'] == "variable":
				
				if right['kind'] == "variable":
					
					if right['name'] in variables:
						if right['name']:
							variables[left['name']] = True
							return True
						
					else:
						print(red("FAILED TO MATCH VARIABLES."))
						sys.exit(43)
				
				# if right is not directly a variable dfs the branch to find one
				else:
					stack = [right]
					while stack:
						node = stack.pop()
						for k, v in node.iteritems():
							if node['kind'] == "variable":
								if node['name'] in variables:
									if node['name']:
										variables[left['name']] = True
										#return True
								
							elif isinstance(v, dict):
								stack.append(v)
								
							elif isinstance(v, list):
								for node in v:
									stack.append(node)
			
		# else look for other assignments
		elif isinstance(v, dict):
			if propagate_taint(v, variables):
				return True
			
		elif isinstance(v, list):
			for node in v:
				if propagate_taint(node, variables):
					return True
	
	return False



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




def get_variables_as_dict(ast):
	
	variables = {}
	
	for k, v in ast.iteritems():
		if k == "kind" and v == "variable":
			variables[ast['name']] = False
			
		elif isinstance(v, dict):
			variables.update(get_variables(v))
			
		elif isinstance(v, list):
			for node in v:
				variables.update(get_variables(node))
		
	return variables



def get_simple_ast(ast):
	
	simpleAST = {}
	visited = []
	stack = []
	stack.append(ast)
	#visited, stack = set(), [ast['children']]
	
	while stack:
		
		node = stack.pop()
		visited.append(node)
		
		
		kind = node['kind']
		
		key = ''
		
		if kind == 'program':
			key = 'children'
			
		elif kind == 'assign':
			key = 'right'
			
		elif kind == 'call':
			key = 'what'
			
		else: # kind == 'identifier'
			key = 'arguments'
			
			
		for child in node['children']:
			stack.append(child)
			
			
	return simpleAST



def analyse_php_ast(ast, patterns):
	
	result = {
		'vulnerability': None
		}
	
	for key, value in ast.iteritems():
		print(key, value)
	
	return result

