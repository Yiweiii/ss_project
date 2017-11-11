
import re


class Node(object):
	
	def __init__(self, type = "???", name = "function", code = None):
		self.type = type
		self.name = name
		
		self.arguments = []
		
		if code != "" and code != None:
			code = code.split(';\n')
			for line in code:
				newNode = None
				
				
				assignment = re.search(r'(\$\w+)=(\S+)', line)
				function = re.search(r'(\w+)\((\S+)\)', line)
				variable = re.search(r'(\$\S+)', line)
				string = re.search(r"['\"](.*?)['\"]", line)
				#string = re.search(r'(.*)', line)
				
				
				if assignment:
					print("a", assignment.group(1),assignment.group(2))
					newNode = Node("variable", assignment.group(1), assignment.group(2))
					
				elif function:
					print("f", function.group(1), function.group(2))
					newNode = Node("function", function.group(1), function.group(2))
					
				elif variable:
					print("v", variable.group(1))
					newNode = Node("variable", variable.group(1))
					
				elif string:
					# FIXME find variables
					print("s", string.group(0))
					newNode = string.group(0)
					
				else:
					print("FAIL")
				
				if newNode:
					self.arguments.append(newNode)
	

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
	

