var express = require('express');
var app = express();
var bodyParser = require('body-parser');
app.use(bodyParser.json());

require('./ekyc/index.js')(app);

app.listen(process.env.PORT || 3000, function () {
	console.log('Squad playground listening on port 3000!')
})