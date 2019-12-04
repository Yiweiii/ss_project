
from extras import yellow

class Vulnerable(object):
	
	
	def __init__(self, name = "vulnerability", entryPoints = None, validation_funcs = None, sensitiveSinks = None):
		self.name = name.strip('\n')
		self.entry_points = [x.strip('\n') for x in entryPoints]
		self.validation_funcs = [x.strip('\n') for x in validation_funcs]
		self.sensitive_sinks = [x.strip('\n') for x in sensitiveSinks]
		
		# fix for ignored '$' from JSON
		for entry in self.entry_points:
			if entry.startswith("$"):
				self.entry_points.append(entry[1:])
	
	
	def __str__(self):
		out = yellow("Name:\t") + self.name + "\n"
		out += yellow("Entry points:\t") + ", ".join(self.entry_points) + "\n"
		out += yellow("Validation functions:\t") + ", ".join(self.validation_funcs) + "\n"
		out += yellow("Sensitive sinks:\t") + ", ".join(self.sensitive_sinks) + "\n"
		
		return out	
	
	
	def __repr__(self):
		#out = " Name: " + self.name
		#out += " Entry points: " + ", ".join(self.entry_points)
		#out += " Escapes: " + ", ".join(self.validation_funcs)
		#out += " Sinks: " + ", ".join(self.sensitive_sinks)
		#return out
		
		return "\n" + str(self)
	
	
	
	def add_entry_point(self, entryPoint):
		
		if not(entryPoint in self.entry_points):
			self.entry_points.append(entryPoint)
			
		return self.entry_points
	
	
	def add_escape(self, escape):
		
		if not(escape in self.validation_funcs):
			self.validation_funcs.append(escape)
			
		return self.validation_funcs
	
	
	def add_sensitive_sinks(self, sensitiveSink):
		
		if not(sensitiveSink in self.sensitive_sinks):
			self.sensitive_sinks.append(sensitiveSink)
			
		return self.sensitive_sinks
	

