

class Color:
	PURPLE = '\033[95m'
	BLUE = '\033[94m'
	CYAN = '\033[96m'
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	RED = '\033[91m'
	END = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	ITALIC = '\x1B[3m'
	

def purple(string): return Color.PURPLE + string + Color.END
def blue(string): return Color.BLUE + string + Color.END
def cyan(string): return Color.CYAN + string + Color.END
def green(string): return Color.GREEN + string + Color.END
def red(string): return Color.RED + string + Color.END
def yellow(string): return Color.YELLOW + string + Color.END

def italic(string): return Color.ITALIC + string + Color.END
def underline(string): return Color.UNDERLINE + string + Color.END
def bold(string): return Color.BOLD + string + Color.END



def print_program_check(variables, tainted, functions, sinks, possiblePatterns):
	
	print(italic("Variables: ") + str(variables))
	print(red(italic("Tainted: ") + red(str(tainted))))
	print(italic("Functions: ") + str(functions))
	print(red(italic("Sinks: ") + red(str(sinks))))
	print(italic(yellow("Possible patterns of vulnerability: ")) + str(possiblePatterns))



def print_stack(stack, name = ""):
	
	if name is None:
		for n in stack:
			print(n)
		
	else:
		print(name)
		for n in stack:
			print("\t" + n)



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




################################### deprecated ###################################


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

