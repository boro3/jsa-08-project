const usersModel = require('../../../pkg/users');
const usersValidator = require('../../../pkg/users/validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cfg = require('../../../pkg/config');


const create = async (req, res) => {
    // validate input data
    try {
        await usersValidator.validate(req.body, usersValidator.registrationSchema);
    } catch (err) {
        console.log(err);
        return res.status(400).send('Bad Request!');
    }
    //check if user already exists
    try {
        let ru = await usersModel.getOneByEmail(req.body.email);
        if (ru) {
            return res.status(409).send('Conflict!');
        }
    } catch (err) {
        console.log(err);
        return res.status(500).send('Internal Server Error!');
    }
    // hasing password
    req.body.password = bcrypt.hashSync(req.body.password);
    // set default data for single user
    req.body.active = true;
    req.body.role = 'user';
    req.body._created = new Date();
    req.body._deleted = false;
    try {
        let u = await usersModel.save(req.body);
        res.status('201').send(u);
    } catch (err) {
        console.log(err);
        return res.status(500).send('Internal Server Error!');
    }
};

const login = async (req, res) => {
    //validate user data
    try {
        await usersValidator.validate(req.body, usersValidator.loginSchema);
    } catch (err) {
        console.log(err);
        return res.status(400).send('Bad Request!');
    }
    //get user
    try {
        let ru = await usersModel.getOneByEmail(req.body.email);
        if (!ru) {
            return res.status(403).send('Forbidden!');
        }
        if (bcrypt.compareSync(req.body.password, ru.password)) {
            let payload = {
                uid: ru._id,
                role: ru.role,
                first_name: ru.first_name,
                last_name: ru.last_name,
                email: ru.email,
                exp: (new Date().getTime() + (365 * 24 * 60 * 60 * 1000)) / 1000
            };
            let key = cfg.get('server').jwt_key;
            let token = jwt.sign(payload, key);
            return res.status(200).send({ jwt: token })
        }
        return res.status(401).send('Unauthorized!');
    } catch (err) {
        console.log(err);
        return res.status(500).send('Internal Server Error!');
    }
    //
};
const refreshToken = (req, res) => {
    let payload = {
        uid: req.user._id,
        role: req.user.role,
        first_name: ru.first_name,
        last_name: req.user.last_name,
        email: req.user.email,
        exp: (new Date().getTime() + (365 * 24 * 60 * 60 * 1000)) / 1000
    };
    let key = cfg.get('server').jwt_key;
    let token = jwt.sign(payload, key);
    res.status(200).send({ jwt: token });
};
const forgotPassword = (req, res) => {
    res.status(200).send('ok');
};
const resetPassword = (req, res) => {
    res.status(200).send('ok');
};


const changePassword = async (req, res) => {
    try {
        await usersValidator.validate(req.body, usersValidator.changePasswordSchema);
    } catch (err) {
        console.log(err);
        return res.status(400).send('Bad Request!');
    }

    try {
        let ru = await usersModel.getOneByEmail(req.body.email);
        if (!ru) {
            return res.status(403).send('Forbidden!');
        }
        if (req.body.new_password1 !== req.body.new_password2) {
            return res.status(400).send('Bad Request!');
        }
        if (bcrypt.compareSync(req.body.old_password, ru.password)) {
            ru.password = bcrypt.hashSync(req.body.new_password1);
            await ru.save();
            return res.status(200).send('OK!');
        }
        return res.status(401).send('Unauthorized!');
    } catch (err) {
        console.log(err);
        return res.status(500).send('Internal Server Error!');
    }

};
const listAccounts = async (req, res) => {
    try {
        let userList = await usersModel.getAll();
        if (!userList) {
            return res.status(403).send('Forbidden!');
        }
        res.status(201).send(userList);
    } catch (err) {
        console.log(err);
        return res.status(500).send('Internal Server Error!');
    }
};

module.exports = {
    create,
    login,
    refreshToken,
    forgotPassword,
    resetPassword,
    changePassword,
    listAccounts
};