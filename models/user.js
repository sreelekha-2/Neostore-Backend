const mongoose = require("mongoose");
const Joi = require("joi");
const passwordComplexity = require("joi-password-complexity");
const { ADMIN, USER } = require("../constants");

const User = mongoose.model(
  "user",
  new mongoose.Schema({
    firstName: {
      type: String,
      required: true,
      minLength: 1,
      maxLength: 50,
    },
    lastName: {
      type: String,
      required: true,
      minLength: 1,
      maxLength: 50,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      minLength: 5,
      maxLengh: 255,
    },
    password: {
      type: String,
      required: true,
      minLength: 5,
      maxLength: 1024,
    },
    role: {
      type: String,
      enum: [ADMIN, USER],
      default: USER,
    },
    contactNumber: {
      type: Number,
      min: 1000000000,
      unique: true,
    },
  }, { timestamps: true })
);

const validateUser = (user) => {
  const userSchema = Joi.object({
    firstName: Joi.string().min(0).max(50).required(),
    lastName: Joi.string().min(0).max(50).required(),
    password: Joi.string().min(5).max(50).required(),
    email: Joi.string().email().min(5).max(255).required(),
    contactNumber: Joi.string().min(10).max(10).required(),
  });

  const validationResult = userSchema.validate(user);
  return validationResult;
};

const validatePassword = ({ name, password }) => {
  if (password.toLowerCase().includes(name.toLowerCase())) {
    return { error: "Password cannot contain username" };
  }
  return passwordComplexity().validate(password);
};

module.exports = { User, validateUser, validatePassword };
