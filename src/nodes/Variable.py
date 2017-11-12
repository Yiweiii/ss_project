
class Variable(Node):
	
	def __init__(self, type = "variable", name = "variable"):
		super(type, name)	
	
	
	def __str__(self):
		out = "Type:\t\tvariable"
		out += "Name:\t\t" + self.name + "\n"
		out += "Right:\t" + ", ".join(self.arguments) + "\n"
		
		return out
	
	
	def __repr__(self):		
		return "\n" + str(self)
	
	
	
	#def visit():
		#for arg in right:
			#if arg.tainted:
				#self.tainted = True
				#return True
		
		#return False
	
	
	#def add_argument(self, argument):
		
		#if not(argument in self.right):
			#self.right.append(argument)
			
		#return self.right
	
	