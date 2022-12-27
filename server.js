const http = require('http');
const serverStart = require('./index')
const port = process.env.PORT || 3000;
const server = http.createServer(serverStart);
server.listen(parseInt(port));
console.log(`Server run on Port : ${port}`)