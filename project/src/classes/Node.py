
class Node(object):
	
	def __init__(self, type = "???", name = "function", code = ""):
		self.type = type
		self.name = name
		
		arguments = []
		
		code = code.split(';\n')
		for line in code:
			line = line.replace('\n', '').split('=', 1)
			
			if line[0].startswith('$'):
				newNode = Node.Node("variable", line[0], line[1])
				
			else:
				l = line[0].index('(')
				r = line[0].index(')')
				newNode = Node.Node("function", line[0], line[0][l:r])
			
			arguments.append(newNode)
		
		self.arguments = arguments
	
	
	def __str__(self):
		out = "Type:\t\t" + self.type + "\n"
		out += "Name:\t\t" + self.name + "\n"
		#out += "Arguments:\t" + ", ".join(self.arguments) + "\n"
		out += "Arguments:\t" + self.arguments + "\n"
		
		return out	
	
	
	def __repr__(self):		
		return "\n" + str(self)
	
	
	
	def add_argument(self, argument):
		
		if not(argument in self.arguments):
			self.arguments.append(argument)
			
		return self.arguments
	
	