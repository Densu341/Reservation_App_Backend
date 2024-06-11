const { Users } = require("../models");
const jwt = require("jsonwebtoken");

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user.id);

  const cookieOptions = {
    expires: new Date(Date.now() + parseInt(process.env.JWT_COOKIE_EXPIRES_IN, 10) * 24 * 60 * 60 * 1000),
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') {
    cookieOptions.secure = true;
  }

  res.cookie('jwt', token, cookieOptions);

  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    data: {
      user,
    },
  });
};

exports.registerUser = async (req, res) => {
  try {
    const {password, password_confirm, email, fullname} = req.body

    if(!password || !password_confirm) {
      return res.status(400).json({
        message: "Validation error",
        error: ["Password and password confirm are required"]
      })
    }

    if (password !== password_confirm) {
      return res.status(400).json({
        message: "Validation error",
        error: ["Passwords do not match"],
      });
    }

    const existingUser = await Users.findOne({
      where: { email: email },
    });

    if (existingUser) {
      return res.status(400).json({
        message: "Validation error",
        error: ["User with this email already exists"],
      });
    }

    const Role = require("../models").Role;
    const role = await Role.findOne({
      where: { nama_role: "pengguna" },
    });

    const newUser = await Users.create({
      fullname,
      email,
      password,
      role_id: role.id,
    });

    return res.status(201).json({
      status: "success",
      message: "User created successfully",
    })
  } catch (error) {
    return res.status(400).json({
      message: "Validation error",
      error: [error.message],
    });
  }
};

exports.loginUser = async (req, res) => {
  try {
    const {email, password} = req.body;
    if(!email || !password) {
      return res.status(400).json({
        message: "Validation error",
        error: ["Please Input Email or Password"],
      });
    }

    const userData = await Users.findOne({
      where: {
        email: email,
      },
    });
    if (!userData ||!(await userData.CorrectPassword(password, userData.password))
    ) {
      return res.status(400).json({
        status: "Fail",
        message: "Error Login",
        error: "Invalid Email or Password",
      });
    }
    createSendToken(userData, 200, res);
  } catch (error) {
    return res.status(500).json({
      message: "Internal server error",
      error: [error.message],
    })
  }
};

exports.logoutUser = async (req, res) => {
  res.cookie("jwt", "", {
    expires: new Date(Date.now(0)),
    httpOnly: true,
  });
  res.status(200).json({ status: "logout success" });
};

exports.getMe = async (req, res) => {
  const user = await Users.findByPk(req.user.id);

  if (user) {
    res.status(200).json({
      status: "success",
      data: {
        id: user.id,
        fullname: user.fullname,
        email: user.email,
        role_id: user.role_id,
      },
    });
  } else {
    return res.status(404).json({
      status: "fail",
      message: "User not found",
    });
  }
};
