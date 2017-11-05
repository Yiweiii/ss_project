
class Variable(object):
	
	def __init__(self, name = "function", arguments = []):
		self.name = name
		self.arguments = arguments
	
	
	def __str__(self):
		out = "Type:\t\tvariable"
		out += "Name:\t\t" + self.name + "\n"
		out += "Arguments:\t" + ", ".join(self.arguments) + "\n"
		
		return out
	
	
	def __repr__(self):		
		return "\n" + str(self)
	
	
	
	def add_argument(self, argument):
		
		if not(argument in self.arguments):
			self.arguments.append(argument)
			
		return self.arguments
	
	