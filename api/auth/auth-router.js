const router = require("express").Router();
const {
  checkUsernameExists,
  validateRoleName,
  restricted,
} = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const model = require("../users/users-model");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const JWT_S = process.env.JWT_SECRET || JWT_SECRET; // use the dotenv string or the one at secret/index.js

router.post("/register", validateRoleName(), async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const role_name = req.role_name;
    const user = await model.findBy({ username });
    const newUser = await model.add({
      username,
      password: await bcrypt.hash(password, 12),
      role_name,
    });
    if (user && user.length >= 1) {
      return res.status(409).json({ message: "Username already taken" });
    } else {
      return res.status(201).json(newUser);
    }
  } catch (err) {
    next(err);
  }
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});

router.post("/login", checkUsernameExists(), async (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  try {
    const { username, password } = req.body;
    const user = await model.findBy({ username });
    if (!user) {
      return res.status(418).json({ message: "user does not exist" });
    }
    const passwordValid = await bcrypt.compare(password, user.password);
    if (!passwordValid) {
      return res.status(401).json({ message: "invalid credentials" });
    }
    const token = jwt.sign(
      {
        subject: user.user_id,
        username: user.username,
        role_name: user.role_name,
        expiresIn: "12h",
      },
      JWT_S
    );
    res.cookie("token", token);
    res.json({
      message: `welcome ${user.username}`,
      token: token,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
