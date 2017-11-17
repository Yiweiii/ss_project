

#FIXME
def get_assignment(ast, variable):
	
	node = None	
	
	for k, v in ast.iteritems():
		if k == "kind" and v == "assign":			
			left = ast['left']
			
			varsOnRight = get_variables(ast['right'])
			
			print([x['name'] for x in varsOnRight])
			
			if variable not in varsOnRight:
				if left['id'] > variable['id']:
					return ast	
			
		elif isinstance(v, dict):
			node = get_assignment(v, variable)
			#if node is not None:
				#break
			
		elif isinstance(v, list):
			for n in reversed(v): # right to left
				node = get_assignment(n, variable)
				if node is not None:
					break
		
	return node



# returns right most assignment node (the closest to the variable use) of the given variable
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



# returns a list of variable nodes under a given node
def get_variables(node):
	
	variables = []
	
	if isinstance(node, dict):
		for k, v in node.iteritems():
			if k == "kind" and v == "call":
				continue;
				
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
def get_calls(ast):
	
	calls = []
	
	if isinstance(ast, dict):
		for k, v in ast.iteritems():
			if k == "kind" and v == "call":
				calls.append(ast)
				
			elif k == "kind" and v == "echo":
				calls.append(ast)
				
			elif isinstance(v, dict):
				calls = calls + get_calls(v)
				
			elif isinstance(v, list):
				for node in v:
					calls = calls + get_calls(v)
				
	elif isinstance(ast, list):
		for node in ast:
			calls = calls + get_calls(node)
	
	return calls








