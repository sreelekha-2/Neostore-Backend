const { validateAddress } = require("../models/address");
const { Address } = require("../models/address");

async function addAddress(req, res) {
    
    const user = req.user;
    // const {error} = validateAddress(req.body);
    // if(error) {
    //     return res.status(400).send(`Bad Request ${error}`);
    // }

    try {
        const address = new Address({...req.body, user: user._id});
        const savedAddress = await address.save();
        return res.send({"err":0,"msg":{...savedAddress}});
    } catch(ex) {
        return res.send({"err":1,"msg":ex.message});
    }
}

async function getAddresses(req, res) {
    const user = req.user;

    try {
        const addresses = await Address.find({user: user._id});
        return res.send({"err":0,"address":addresses});
    } catch(ex) {
        return res.status(400).send(ex.message);
    }
}

module.exports = {
    addAddress,
    getAddresses
}