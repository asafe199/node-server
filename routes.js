const express = require('express');
const app = express.Router();
const CONTROLLER = require('./controller/controller.js');

app.post("/ally", CONTROLLER.allyCreateToken);

module.exports = app;