const ROUTES = require('./routes');

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const PATH_CONTEXT = '/api';

var CORS_CONFIG = {
  "origin": "*",
  "methods": "GET,HEAD,PUT,PATCH,POST,DELETE",
  "preflightContinue": false,
  "optionsSuccessStatus": 204
};

const app = express();
app.use(cors(CORS_CONFIG));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(`${PATH_CONTEXT}/controller`, ROUTES);

app.use((req, res, next) => {
  const err = new Error('Resource not found');
  err.status = 404;
  next(err);
});

app.use(function (err, req, res, next) {
  res.status(err.status).send({
      data: err.message
  });
});

module.exports = app;