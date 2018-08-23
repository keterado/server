var config = require('config.json');
var _ = require('lodash');
var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var Q = require('q');
var mongo = require('mongoskin');
var db = mongo.db(config.connectionString, { native_parser: true });
var dbROOT = mongo.db(config.connectionString, { native_parser: true });
db.bind('admins');
dbROOT.bind('ROOT');

var service = {};

service.authenticate = authenticate;
service.getAll = getAll;
service.getById = getById;
service.create = create;
service.update = update;
service.delete = _delete;

module.exports = service;

function authenticate(correo, clave) {
    var deferred = Q.defer();

    db.admins.findOne({ correo: correo }, function (err, admin) {
        if (err) deferred.reject(err.name + ': ' + err.message);

        if (admin && bcrypt.compareSync(clave, admin.hash)) {
            // authentication successful
            deferred.resolve({
                _id: admin._id,
                correo: admin.correo,
                nombres: admin.nombres,
                apellidos: admin.apellidos,
                cedula: admin.cedula,
                token: jwt.sign({ sub: admin._id }, config.secret)
            });
        } else {
            // authentication failed o verificar si es root
            dbROOT.ROOT.findOne({correo: correo}, function (err, SuAdmin) {
                if (err) deferred.reject(err.name + ': ' + err.message);
// cambie aca, para q compare la clave del root sin hash
                if (SuAdmin.clave == clave) {
                    // authentication successful
                    deferred.resolve({
                        _id: SuAdmin._id,
                        correo: SuAdmin.correo,
                        nombres: SuAdmin.nombres,
                        apellidos: SuAdmin.apellidos,
                        cedula: SuAdmin.cedula,
                        token: jwt.sign({ sub: SuAdmin._id }, config.secret)
                    });
                }else {
                    // aqui falta los trabajadores si es que funca
                    deferred.resolve();
                }
            });
           // deferred.resolve();
        }
    });

    return deferred.promise;
}

function getAll() {
    var deferred = Q.defer();

    db.admins.find().toArray(function (err, admins) {
        if (err) deferred.reject(err.name + ': ' + err.message);

        // return users (without hashed passwords)
        admins = _.map(admins, function (admin) {
            return _.omit(admin, 'hash');
        });

        deferred.resolve(admins);
    });

    return deferred.promise;
}

function getById(_id) {
    var deferred = Q.defer();

    db.admins.findById(_id, function (err, admin) {
        if (err) deferred.reject(err.name + ': ' + err.message);

        if (admin) {
            // return user (without hashed password)
            deferred.resolve(_.omit(admin, 'hash'));
        } else {
            // user not found
            deferred.resolve();
        }
    });

    return deferred.promise;
}

function create(userParam) {
    var deferred = Q.defer();

    // validation
    db.admins.findOne(
        { correo: userParam.correo },
        function (err, admin) {
            if (err) deferred.reject(err.name + ': ' + err.message);

            if (admin) {
                // username already exists
                deferred.reject('Correo "' + userParam.correo + '" is already taken');
            } else {
                createUser();
            }
        });

    function createUser() {
        // set user object to userParam without the cleartext password
        var admin = _.omit(userParam, 'clave');

        // add hashed password to user object
        admin.hash = bcrypt.hashSync(userParam.clave, 10);

        db.admins.insert(
            admin,
            function (err, doc) {
                if (err) deferred.reject(err.name + ': ' + err.message);

                deferred.resolve();
            });
    }

    return deferred.promise;
}

function update(_id, userParam) {
    var deferred = Q.defer();

    // validation
    db.admins.findById(_id, function (err, admin) {
        if (err) deferred.reject(err.name + ': ' + err.message);

        if (admin.correo !== userParam.correo) {
            // username has changed so check if the new username is already taken
            db.admins.findOne(
                { correo: userParam.correo },
                function (err, admin) {
                    if (err) deferred.reject(err.name + ': ' + err.message);

                    if (admin) {
                        // username already exists
                        deferred.reject('Correo "' + req.body.correo + '" is already taken')
                    } else {
                        updateUser();
                    }
                });
        } else {
            updateUser();
        }
    });

    function updateUser() {
        // fields to update
        var set = {
            nombres: userParam.nombres,
            apellidos: userParam.apellidos,
            correo: userParam.correo
        };

        // update password if it was entered
        if (userParam.clave) {
            set.hash = bcrypt.hashSync(userParam.clave, 10);
        }

        db.admins.update(
            { _id: mongo.helper.toObjectID(_id) },
            { $set: set },
            function (err, doc) {
                if (err) deferred.reject(err.name + ': ' + err.message);

                deferred.resolve();
            });
    }

    return deferred.promise;
}

function _delete(_id) {
    var deferred = Q.defer();

    db.admins.remove(
        { _id: mongo.helper.toObjectID(_id) },
        function (err) {
            if (err) deferred.reject(err.name + ': ' + err.message);

            deferred.resolve();
        });

    return deferred.promise;
}