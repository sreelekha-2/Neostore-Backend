const Joi = require("joi");
const mongoose = require("mongoose");

const Address = mongoose.model(
  "address",
  new mongoose.Schema({
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "user",
    },
    name: {
      type: String,
      required: true,
    },
    contactNumber: {
      type: Number,
      required: true,
    },
    city: {
      type: String,
      required: true,
    },
    landmark: {
      type: String,
    },
    street: {
      type: String,
      required: true,
    },
    state: {
      type: String,
      required: true,
    },
    zipCode: {
      type: Number,
      required: true,
    },
  }, { timestamps: true })
);

const validateAddress = (address) => {
    const addressSchema = Joi.object({
      name: Joi.string().min(0).max(50).required(),
      contactNumber: Joi.number().min(1000000000).max(99999999999).required(),
      city: Joi.string().min(0).max(50).required(),
      zipCode: Joi.number().min(100000).max(999999).required(),
      landmark: Joi.optional(),
      state: Joi.required(),
      street: Joi.required()
    });
  
    const validationResult = addressSchema.validate(address);
    return validationResult;
  };

module.exports = { Address, validateAddress };
