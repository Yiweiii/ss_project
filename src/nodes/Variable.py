
class Variable(Node):
	
	def __init__(self, type = "variable", name = "variable", right = []):
		super(type, name)
		self.right = right
	
	
	def __str__(self):
		out = "Type:\t\tvariable"
		out += "Name:\t\t" + self.name + "\n"
		out += "Right:\t" + ", ".join(self.right) + "\n"
		
		return out
	
	
	def __repr__(self):		
		return "\n" + str(self)
	
	
	
	def visit():
		for arg in right:
			if arg.tainted:
				self.tainted = True
				return True
		
		return False
	
	
	def add_argument(self, argument):
		
		if not(argument in self.right):
			self.right.append(argument)
			
		return self.right
	
	