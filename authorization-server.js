const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/

app.get('/authorize', (req, res) => {
	// Get the client_id and scopes params from the query object
	const clientId = req.query.client_id;
	console.log('req.query.scopes....',req.query.scope)
	const requestedScopes = req.query.scope ? req.query.scope.split(' ') : [];
	
	// Determine if the client ID exists in the clients object
	if (!clients[clientId]) {
	  // If the client ID does not exist, respond with a 401 status code and return
	  res.status(401).send('Invalid client ID');
	  return;
	}
  
	console.log('requestedScopes....',requestedScopes)
	// Get the allowed scopes for the client
	const allowedScopes = clients[clientId].allowedScopes;

	// check if the client ID exists and scopes are allowed
	if (!clients[clientId] || !containsAll(clients[clientId].scopes, req.query.scope.split(' '))) {
		return res.status(401).send('Unauthorized');
	  }
	  
	  const requestId = randomString();
	  requests[requestId] = req.query;

	  // If the client ID and scopes are valid, render the login page
	  const client = clients[clientId];
	  const scope = req.query.scope;
	  const params = { client, scope, requestId };
	  res.render('login', params);
	  //res.status(200).send('Valid client ID and scope');
  });

  app.post('/approve',(req,res)=>{
	const { userName, password, requestId} = req.body;

  // Check if the username and password match
  if (users[userName] !== password) {
    // If the username and password don't match, respond with a 401 status code and return
    res.status(401).send('Invalid username or password');
    return;
  }

  // Check if the request exists
  if (!requests[requestId]) {
    return res.status(401).end();
  }

  // Assign the request to a local variable and delete it from the requests object
  var clientRequest = requests[requestId];
  delete requests[requestId];


  // Retain the client request and the userName of the logged in user in authorizationCodes
  var code = 'rof5ijf';
  authorizationCodes[code] = {
    clientReq: clientRequest,
    userName: userName
  };

  // Send a redirect response to the client request's redirect URI with the code and state as query params
  var redirectURI = clientRequest.redirect_uri;
  var state = clientRequest.state;

  var redirectURL = redirectURI + '?code=' + code + '&state=' + state;
  res.redirect(redirectURL);
  })


app.post('/token',(req,res)=>{
	
	if (!req.headers.authorization) {
		return res.status(401).send('Unauthorized');
	  }

	  const authCredentials = decodeAuthCredentials(req.headers.authorization);

  // Check if the client ID and secret match
//   const client = clients[authCredentials.clientId];
//   if (client.secret !== authCredentials.clientSecret) {
//     return res.status(401).send("Invalid client credentials");
//   }

  // Check if the code exists in the authorizationCodes object
  const obj = authorizationCodes[req.body.code];

  if (!obj) {
    return res.status(401).send("Invalid code");
  }

  // Delete the code from authorizationCodes
  delete authorizationCodes[req.body.code];


  const payload = { userName: obj.userName, scope: obj.clientReq.scope };
  
  const signOptions = { algorithm: 'RS256' };
  const token = jwt.sign(payload, config.privateKey, signOptions);

  // Respond with token
  res.status(200).json({
    access_token: token,
    token_type: 'Bearer'
  });
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
