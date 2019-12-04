
# returns right most assignment node (the closest to the variable use) of the given variable
def get_assignment(ast, variable):
	
	node = None	
	
	for k, v in ast.iteritems():
		if k == "kind" and v == "assign":		
			left = ast['left']
			
			#if left['kind'] == "variable" and left['name'] == variable['name']:
				#return ast	
			
			
			varsOnRight = get_variables(ast['right'])
			
			if variable['name'] in [x['name'] for x in varsOnRight]:
				if left['kind'] == "variable" and left['name'] == variable['name']:
					if left['id'] > variable['id']:
						return ast
				
			else:
				if left['kind'] == "variable" and left['name'] == variable['name']:
					return ast
			
			
		elif isinstance(v, dict):
			node = get_assignment(v, variable)
			if node is not None:
				break
			
			
		elif isinstance(v, list):
			for n in reversed(v): # right to left
				node = get_assignment(n, variable)
				if node is not None:
					break
		
	return node



# returns a list of variable nodes under a given node
def get_variables(node):
	
	variables = []
	
	if isinstance(node, dict):
		for k, v in node.iteritems():
			if k == "kind" and v == "call":
				continue
				
			elif k == "kind" and v == "variable":
				variables.append(node)
				
			elif isinstance(v, dict):
				variables = variables + get_variables(v)
				
			elif isinstance(v, list):
				for n in v:
					variables = variables + get_variables(n)
				
	elif isinstance(node, list):
		for n in node:
			variables = variables + get_variables(n)
	
	return variables



# returns a list of function nodes under a given node
def get_functions(ast):
	
	functions = []
	
	if isinstance(ast, dict):
		for key, value in ast.iteritems():
			if key == "kind" and value == "call":
				functions.append(ast)
				
			elif key == "kind" and value == "echo":
				functions.append(ast)
				
			elif isinstance(value, dict):
				functions = functions + get_functions(value)
				
			elif isinstance(value, list):
				for node in value:
					functions = functions + get_functions(value)
				
	elif isinstance(ast, list):
		for node in ast:
			functions = functions + get_functions(node)
	
	
	return functions





# DEPRECATED returns right most assignment node (the closest to the variable use) of the given variable
def get_assign(ast, variable):
	
	node = None	
	
	for k, v in ast.iteritems():
		if k == "kind" and v == "assign":			
			left = ast['left']
			
			if left['kind'] == "variable" and left['name'] == variable:
				return ast	
			
		elif isinstance(v, dict):
			node = get_assign(v, variable)
			if node is not None:
				break
			
		elif isinstance(v, list):
			for n in reversed(v):
				node = get_assign(n, variable)
				if node is not None:
					break
		
	return node



