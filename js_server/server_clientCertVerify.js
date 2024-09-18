const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('./server.key'),
  cert: fs.readFileSync('./server.crt'),
  ca: [fs.readFileSync('./client.crt')],
  requestCert: true,
  rejectUnauthorized: true,
  passphrase: 'hello'
};

https.createServer(options, (req, res) => {
  const clientCert = req.connection.getPeerCertificate();
  if (req.client.authorized) {
    console.log('client certificate:', clientCert);
    res.writeHead(200);
    res.end('mTLS connection OK! - client cert explicitly verified');
  } else {
    console.log('client cert not authorized.');
    res.writeHead(401);
    res.end('unauthorized');
  }
}).listen(4444, () => {
  console.log('server is running on port 4444');
});
