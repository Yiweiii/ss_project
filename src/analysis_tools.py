

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

