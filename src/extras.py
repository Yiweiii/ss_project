
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
        
def green(string): return Color.GREEN + string + Color.END
def red(string): return Color.RED + string + Color.END
def yellow(string): return Color.YELLOW + string + Color.END

def italic(string): return Color.ITALIC + string + Color.END
def underline(string): return Color.UNDERLINE + string + Color.END
def bold(string): return Color.BOLD + string + Color.END



def print_program_check(variables, tainted, functions, sinks, possiblePatterns):
	
	print(italic("Program variables: ") + str(variables))
	print(italic("Tainted: ") + str(tainted))
	print(italic("Functions: ") + str(functions))
	print(italic("Sinks: ") + str(sinks))
	print(italic(yellow("Possible patterns of vulnerability: ")) + str(possiblePatterns))



def find_assign(ast, variable):
	
	node = None
	
	for k, v in ast.iteritems():
		if k == u"kind" and v == u"assign":
			if ast['left']['kind'] == "variable" and ast['left']['name'] == variable:
				node = ast
			
		elif isinstance(v, dict):
			node = find_assign(v, variable)
			
		elif isinstance(v, list):
			for element in v:
				node = find_assign(element, variable)
		
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



def get_variables(ast):
	
	variables = set()
	#print("\n" + str(ast) + "\n")
	
	if isinstance(ast, dict):
		for k, v in ast.iteritems():
			if k == "kind" and v == "variable":
				variables.add(ast['name'])
				
			elif isinstance(v, dict):
				#variables = variables + get_variables(v)
				variables.update(get_variables(v))
				
			elif isinstance(v, list):
				for node in v:
					#variables = variables + get_variables(v)
					variables.update(get_variables(v))
				
	elif isinstance(ast, list):
		for node in ast:
			#variables = variables + get_variables(node)
			variables.update(get_variables(node))
	
	return variables



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



