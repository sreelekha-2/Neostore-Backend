const mongoose = require("mongoose");

const Product = mongoose.model(
  "product",
  new mongoose.Schema({
    name: {
      type: String,
      required: true,
    },
    category: {
      type: String,
      required: true,
    },
    price: {
      type: Number,
      required: true,
    },
    description: {
      type: String,
    },
    manufacturer: {
      type: String,
    },
    availableItems: {
      type: Number,
      required: true,
    },
    imageURL: {
      type: String,
    },
  }, { timestamps: true })
);

module.exports = { Product };
