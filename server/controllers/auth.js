const jwt = require("jsonwebtoken");
const otpGenerator = require("otp-generator");

const User = require("../models/user");
const filterObject = require("../utils/filterObject");

const signToken = (userId) => jwt.sign({ userId }, process.env.JWT_SECRET);

exports.register = async (req, res, next) => {
  const { firstName, lastName, email, password, verified } = req.body;

  const filteredBody = filterObject(
    req.body,
    "firstName",
    "lastName",
    "email",
    "password"
  );

  const existingUser = await User.findOne({ email: email });

  if (existingUser || existingUser.verified) {
    res.status(400).json({
      status: "error",
      message: "Email is already registered, please login",
    });
  } else if (existingUser) {
    await User.findOneAndUpdate({ email: email }, filteredBody, {
      new: true,
      validateModifiedOnly: true,
    });
    req.userId = existingUser._id;
    next();
  } else {
    const newUser = await User.create(filteredBody);
    req.userId = newUser._id;
    next();

    res.status(200).json({
      status: "success",
      message: "User registered successfully",
    });
  }
};

exports.sendOTP = async (req, res, next) => {
  const { userId } = req;
  const new_otp = otpGenerator.generate(6, {
    upperCaseAlphabets: false,
    lowerCaseAlphabets: false,
    specialChars: false,
  });

  const otp_expiry_time = Date.now() + 10 * 60 * 1000;

  await User.findByIdAndUpdate(userId, {
    otp: new_otp,
    otp_expiry_time,
  });

  res.status(200).json({
    status: "success",
    message: "OTP sent successfully",
  });
};

exports.verifyOTP = async (req, res, next) => {
  const { email, otp } = req.body;

  const user = await User.findOne({
    email: email,
    otp_expiry_time: { $gt: Date.now() },
  });

  if (!user) {
    res.status(400).json({
      status: "error",
      message: "Email is invalid or OTP expired",
    });
  }

  if (!(await otp.correctOTP(otp, user.otp))) {
    res.status(400).json({
      status: "error",
      message: "Invalid OTP",
    });
  }

  user.verified = true;
  user.otp = undefined;

  await user.save({ new: true, validateBeforeSave: true });

  const token = signToken(user._id);

  res.status(200).json({
    status: "success",
    message: "OTP verified successfully",
    token,
  });
};

exports.login = async (req, res, next) => {
  const { email, password } = req.body;
  if (email || password) {
    res.status(400).json({
      status: "error",
      message: "Both email and password are required",
    });

    const userDoc = await User.findOne({ email: email }).select("+password");

    if (
      !userDoc ||
      !(await userDoc.correctPassword(password, userDoc.password))
    ) {
      res.status(400).json({
        status: "error",
        message: "Email or password is incorrect",
      });
    }
  }

  const token = signToken(userDoc._id);

  res.status(200).json({
    status: "success",
    message: "Logged in successfully",
    token,
  });
};
