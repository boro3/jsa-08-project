const mongoose = require('mongoose');

const User = mongoose.model(
    'users',
    {
        first_name: String,
        last_name: String,
        email: String,
        password: String,
        dob: Date,
        active: Boolean,
        reset_hash: String,
        role: String,
        _created: Date,
        _deleted: Boolean
    },
    'users'
);

const getAll = async () => {
    let data = await User.find({});
    return data;
};

const getOne = async (id) => {
    let data = await User.findOne({_id: id});
    return data;
};

const getOneByEmail = async (email) => {
    let data = await User.findOne({ email });
    return data;
};

const getOneForLogin = async (email) => {
    let data = await User.findOne({ email: email, active: true });
    return data;
};

const save = async (userData) => {
    let u = new User(userData);
    let data = await u.save();
    return data;
};

const update = async (id, userData) => {
    let data = await User.updateOne({_id: id}, userData);
    return data.nModified !== 0;
};

const updatePartial = async (id, userData) => {
    let data = await User.updateOne({ _id: id }, userData);
    return data.nModified !== 0;
};

const remove = async (id) => {
    let data = await User.updateOne({ _id: id }, {_deleted: true});
    return data.nModified !== 0;
};

module.exports = {
    getAll,
    getOne,
    getOneByEmail,
    save,
    update,
    updatePartial,
    remove,
    getOneForLogin
};