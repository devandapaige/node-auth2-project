const { JWT_SECRET, JWT_SECRET } = require("../secrets"); // use this secret!
//also have a secret token in process.env.JWT_SECRET
const jwt = require("jsonwebtoken");
const model = require("../users/users-model");

const JWT_S = process.env.JWT_SECRET || JWT_SECRET; // use the dotenv string or the one at secret/index.js

const restricted = () => async (req, res, next) => {
  try {
    const token = req.headers.auth;
    if (!token) {
      return res, status(401).json({ message: "Token required" });
    } else {
      jwt.verify(token, JWT_S, (err, decoded) => {
        if (err) {
          return res.status(401).json({ message: "Token Invalid" });
        } else {
          req.token = decoded;
        }
      });
      next();
    }
  } catch (err) {
    next(err);
  }
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
};

const only = (role_name) => (req, res, next) => {
  const token = req.token;
  if (token.role_name !== role_name) {
    return res.status(403).json({
      message: "This is not for you",
    });
  }
  next();
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
};

const checkUsernameExists = () => async (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
  try {
    const { username } = req.body;
    const findInData = await model.findBy({ username });
    if (!findInData) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (err) {
    next(err);
  }
};

const validateRoleName = () => async (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
  if (req.body.role_name) {
    req.role_name = req.body.role_name.trim();
  }
  if (!req.body.role_name || req.role_name.length === 0) {
    req.role_name = "student";
  }
  if (req.role_name == "admin") {
    return res.status(422).json({ message: "Role name cannot be admin" });
  }
  if (req.role_name.length > 32) {
    return res
      .status(422)
      .json({ message: "Role name can not be longer than 32 chars" });
  }
  next();
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
