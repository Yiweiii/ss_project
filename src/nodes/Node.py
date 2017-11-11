

class Node(object):
	
	def __init__(self, type = "Node", name = "node", tainted = False):
		self.type = type
		self.name = name
		self.tainted = tainted
	
	

	def __str__(self):
		out = "Type:\t\t" + self.type + "\n"
		out += "Name:\t\t" + self.name + "\n"
		#out += "Arguments:\t" + ", ".join(self.arguments) + "\n"
		out += "Arguments:\t" + self.arguments + "\n"
		
		return out	
	
	
	
	def __repr__(self):		
		return "\n" + str(self)
	
	
	@abstractmethod
	def visit():
		return self.tainted
	

