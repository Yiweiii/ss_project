

def analyse_php_ast(ast, patterns):
	
	result = {
		'vulnerability': None
		}
	
	for key, value in ast.iteritems():
		print(key, value)
	
	return result

