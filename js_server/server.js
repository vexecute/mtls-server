const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('./server.key'),
  cert: fs.readFileSync('./server.crt'),
  ca: [fs.readFileSync('./client.crt')],
  requestCert: true,
  rejectUnauthorized: true, 
  passphrase: 'hello', 
};

https.createServer(options, (req, res) => {
  res.writeHead(200);
  res.end('mTLS established!');
}).listen(4444, () => {
  console.log('server is running on port 4444');
});
