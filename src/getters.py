

def get_assign(ast, variable):
	node = None	
	
	#for k, v in sorted(ast.iteritems(), reverse=True):
	for k, v in ast.iteritems():
		if k == "kind" and v == "assign":			
			left = ast['left']
			
			if left['kind'] == "variable" and left['name'] == variable:
				return ast	
			
		elif isinstance(v, dict):
			return get_assign(v, variable)
			
		elif isinstance(v, list):
			for element in reversed(v):
				node = get_assign(element, variable)
				if node is not None:
					break
			
	return node



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



def get_variable_names(ast):
	
	variables = set()
	
	if isinstance(ast, dict):
		for k, v in ast.iteritems():
			if k == "kind" and v == "variable":
				variables.add(ast['name'])
				
			elif isinstance(v, dict):
				#variables = variables + get_variable_names(v)
				variables.update(get_variable_names(v))
				
			elif isinstance(v, list):
				for node in v:
					#variables = variables + get_variable_names(v)
					variables.update(get_variable_names(v))
				
	elif isinstance(ast, list):
		for node in ast:
			#variables = variables + get_variable_names(node)
			variables.update(get_variable_names(node))
	
	return variables


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


def get_calls(ast):
	
	#print(green(str(ast)))
	#print("")
	
	calls = []
	
	if isinstance(ast, dict):
		for k, v in ast.iteritems():
			if k == "kind" and v == "call":
				calls.append(ast)
				
			elif isinstance(v, dict):
				calls = calls + get_calls(v)
				
			elif isinstance(v, list):
				for node in v:
					calls = calls + get_calls(v)
				
	elif isinstance(ast, list):
		for node in ast:
			calls = calls + get_calls(node)
			
	#print(yellow(str(calls)))
	#print("")
	
	return calls



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



