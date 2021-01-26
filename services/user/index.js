const cfg = require('../../pkg/config');
require('../../pkg/db');

const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('express-jwt');

const users = require('./handlers/users');

const api = express();

api.use(bodyParser.json());
api.use(jwt({
    secret: cfg.get('security').jwt_key,
    algorithms: ['HS256']
}));
api.use(function (err, req, res, next) {
    if (err.name === 'UnauthorizedError') {
        res.status(401).send('Bad JWT');
    }
});

api.get('/api/v1/users', users.getAll);
api.get('/api/v1/users/:id', users.getOne);
api.post('/api/v1/users', users.save);
api.put('/api/v1/users/:id', users.update);
api.patch('/api/v1/users/:id', users.updatePartial);
api.delete('/api/v1/users/:id', users.remove);

api.listen(cfg.get('services').users.port, err => {
    if (err) {
        return console.error(err);
    }
    console.log(`Server successfully started on port ${cfg.get('services').users.port}`);
});