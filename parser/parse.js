// initialize the php parser factory class
var fs = require('fs');
var path = require('path');
var engine = require('php-parser');

// initialize a new parser instance
var parser = new engine({
  // some options :
  parser: {
    extractDoc: true,
    php7: true
  },
  ast: {
    withPositions: false
  }

});

const directoryPath = path.join('.', 'slices', 'php');


fs.readdir(directoryPath, function (err, files) {
    //handling error
    if (err) {
        return console.log('Unable to scan directory: ' + err);
    } 
    //listing all files using forEach
    files.forEach(function (file) {
        // Do whatever you want to do with the file
        console.log(file);
		
		const filePath = path.join('.', 'slices', 'php', file);

        var phpFile = fs.readFileSync(filePath);

        const outPath = path.join('.', 'slices', path.parse(file).name+'.json');

        console.log(outPath);

		fs.writeFile(outPath, JSON.stringify(parser.parseCode(phpFile)), (err) => {
			if (err) throw err;
		});

 });
});

// // Retrieve the AST from the specified source
// var eval = parser.parseEval('echo "Hello World";');

// // Retrieve an array of tokens (same as php function token_get_all)
// var tokens = parser.tokenGetAll('<?php echo "Hello World";');

// Load a static file (Note: this file should exist on your computer)

// Log out results
// console.log(parser.parseCode(phpFile));