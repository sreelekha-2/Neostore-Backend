const bcrypt = require("bcrypt");
const { User, validateUser } = require("./../models/user");
const _ = require("lodash");
const jwt = require("jsonwebtoken");
const { AUTH_TOKEN, ADMIN } = require("../constants");

async function signIn(req, res) {
  const { email, password } = req.body;

  let user = await User.findOne({ email });

  if (!user) {
    return res.send({"err":1,"msg":"This email has not been registered!"});
  }

  const validPassword = await bcrypt.compare(password, user.password);

  if (!validPassword) {
    return res.send({"err":1,"msg":"Invalid Credentials!"});
  }

  const token = jwt.sign(
    {
      _id: user._id,
      name: `${user.firstName} ${user.lastName}`,
      isAdmin: user.role === ADMIN,
    },
    "1@3456Qw-"
  );
  res.send({
    name: `${user.firstName} ${user.lastName}`,
    email: user.email,
    isAuthenticated: true,
    token:token,
    err:0
  });
}

async function signUp(req, res) {
  console.log(req.body);
  // res.send("api call")
  // const { error } = validateUser(req.body);
  // if (error) {
  //   return res.status(400).send(`Bad Request ${error}`);
  // }

  let user = await User.findOne({ email: req.body.email });

  if (user) {
    return res
     .send({"err":"1","msg":"Try any other email, this email is already registered!"});
  }

  let userPhone = await User.findOne({ contactNumber: req.body.contactNumber });

  if (userPhone) {
    return res.send({"err":"1","msg":"Number Already exists"});
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const user = new User({
      ...req.body,
      password: await bcrypt.hash(req.body.password, salt),
    });
    const response = await user.save();
    res.send({"err":0,"msg":"User Registered"});
  } catch (ex) {
    res.status(400).send(ex.message);
  }
}

module.exports = {
  signUp,
  signIn,
};
