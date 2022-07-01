const mongoose = require("mongoose");

const Order = mongoose.model(
  "order",
  new mongoose.Schema({
    address: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "address",
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "user",
    },
    product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "product",
    },
    quantity: {
      type: Number,
      required: true,
    },
  }, { timestamps: true })
);

module.exports = { Order };
