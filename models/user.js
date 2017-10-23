const Promise = require('bluebird');
const Sequelize = require('sequelize');
const cls = require('continuation-local-storage');
const ns = cls.createNamespace('transaction-namespace');
const clsBluebird = require('cls-bluebird');
clsBluebird(ns, Promise);
Sequelize.useCLS(ns);

var bcrypt = require('bcrypt');
var _ = require('underscore');

module.exports = function (sequelize, DataTypes) {

	const User = sequelize.define('user', {
		email: {
			type: DataTypes.STRING,
			allowNull: false,
			unique: true,
			validate: {
				isEmail: true
			}
		},
		salt: {
			type: DataTypes.STRING
		},
		password_hash: {
			type: DataTypes.STRING
		},
		password: {
			type: DataTypes.VIRTUAL,
			allowNull: false,
			validate: {
				len: [7, 100]
			},
			set: function (value) {
				var salt = bcrypt.genSaltSync(10);
				var hashedPassword = bcrypt.hashSync(value, salt);

				this.setDataValue('password', value);
				this.setDataValue('salt', salt);
				this.setDataValue('password_hash', hashedPassword);
			}
		}
	}, {
		hooks: {
			beforeValidate: function (user, options) {
				if (typeof user.email === 'string') {
					user.email = user.email.toLowerCase();
				}
			}
		}
	});


	//Class Methods
	User.authenticate = function (body) {
		return new Promise(function (resolve, reject) {
			if (typeof body.email !== 'string' || typeof body.password !== 'string') {
				return reject();
			}

			User.findOne({
				where: {
					email: body.email
				}
			}).then(function (user) {

				if (!user || !bcrypt.compareSync(body.password, user.get('password_hash'))) {
					return reject();
				}

				return resolve(user);

			}, function () {
				return reject();
			});
		});
	}

	//Instance Mehtod
	User.prototype.toPublicJSON = function () {
		var json = this.toJSON();
		return _.pick(json, 'id', 'email', 'createdAt', 'updatedAt');
	}

	return User;
};