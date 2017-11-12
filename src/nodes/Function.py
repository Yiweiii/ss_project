
class Function(Node):
	
	def __init__(self, type = "Function", name = "function", arguments = []):
		super(type, name)
	
	
	
	def __str__(self):
		out = "Type:\t\tfunction"
		out += "Name:\t\t" + self.name + "\n"
		out += "Arguments:\t" + ", ".join(self.arguments) + "\n"
		
		return out	
	
	
	def __repr__(self):		
		return "\n" + str(self)
	
	
	
	#def visit():
		#for arg in arguments:
			#if arg.tainted:
				#self.tainted = True
				#return True
		
		#return False
	
	
	
	#def add_argument(self, argument):
		
		#if not(argument in self.arguments):
			#self.arguments.append(argument)
			
		#return self.arguments
	
	