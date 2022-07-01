const { Address } = require("../models/address");
const { Order } = require("../models/order");
const { Product } = require("../models/product");

async function createOrder(req, res) {
   
    const product = await Product.findById(req.body.product);

    if(!product) {
        return res.status(400).send(`No Product found for ID - ${req.body.product}!`);
    }

    const address = await Address.findById(req.body.address);
    if(!address) {
        return res.status(400).send(`No address found for ID - ${req.body.address}!`);
    }

    if(product.availableItems < req.body.quantity) {
        return res.status(400).send(`Product with ID - ${req.body.product} is currently out of stock!`);
    }

    try {
        const order = new Order({...req.body, user: req.user._id});
        const savedOrder = order.save();

        const updatedProduct = await Product.findById(product);
        updatedProduct.availableItems -= +req.body.quantity;
        await updatedProduct.save();

        return res.send({"err":0,"msg":savedOrder});
    } catch(ex) {
        return res.status(400).send(ex.message);
    }
}

module.exports = {
    createOrder
}