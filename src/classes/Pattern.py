
class Pattern(object):
	
	
	def __init__(self, name = "vulnerability", entryPoints = None, escapes = None, sensitiveSinks = None):
		self.name = name.strip('\n')
		self.entry_points = [x.strip('\n') for x in entryPoints]
		self.escapes = [x.strip('\n') for x in escapes]
		self.sensitive_sinks = [x.strip('\n') for x in sensitiveSinks]
	
	
	def __str__(self):
		out = "Name:\t\t" + self.name + "\n"
		out += "Entry points:\t" + ", ".join(self.entry_points) + "\n"
		out += "Escapes:\t" + ", ".join(self.escapes) + "\n"
		out += "Sinks:\t\t" + ", ".join(self.sensitive_sinks) + "\n"
		
		return out	
	
	
	def __repr__(self):
		#out = " Name: " + self.name
		#out += " Entry points: " + ", ".join(self.entry_points)
		#out += " Escapes: " + ", ".join(self.escapes)
		#out += " Sinks: " + ", ".join(self.sensitive_sinks)
		#return out
		
		return "\n" + str(self)
	
	
	
	def add_entry_point(self, entryPoint):
		
		if not(entryPoint in self.entry_points):
			self.entry_points.append(entryPoint)
			
		return self.entry_points
	
	
	def add_escape(self, escape):
		
		if not(escape in self.escapes):
			self.escapes.append(escape)
			
		return self.escapes
	
	
	def add_sensitive_sinks(self, sensitiveSink):
		
		if not(sensitiveSink in self.sensitive_sinks):
			self.sensitive_sinks.append(sensitiveSink)
			
		return self.sensitive_sinks
	

