

class Node(object):
	
	def __init__(self, type = "Node", name = "node", arguments = [], tainted = False):
		self.type = type
		self.name = name
		self.tainted = tainted
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
		
		if not(argument in self.right):
			self.right.append(argument)
			
		return self.right
	
	
	
	@abstractmethod
	def visit(leadingSpaces = 0):
		print("  "*leadingSpaces + "visited " + self.type + " " + self.name + ".")
		
		for node in self.arguments
			node.visit(leadingSpaces + 1)
		
	
	
	
	@abstractmethod
	def is_tainted():
		
		if self.tainted:
			return True
			
		else:
			for node in arguments:
				if node.is_tainted():
					self.tainted = True
					return True
		
		return False
	
	
	
