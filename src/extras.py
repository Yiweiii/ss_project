

def italic(string):
	return "\x1B[3m" + string + "\x1B[23m"



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




def get_variables_dict(ast):
	
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

