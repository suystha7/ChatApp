const jwt = require("jsonwebtoken"); 
const otpGenerator = require("otp-generator"); 
const crypto = require("crypto"); 

const User = require("../models/user"); 
const filterObject = require("../utils/filterObject"); 
const { promisify } = require("util"); 

// Function to sign a JWT token for a user
const signToken = (userId) => jwt.sign({ userId }, process.env.JWT_SECRET);

// Register a new user or update an existing unverified user
exports.register = async (req, res, next) => {
  const { firstName, lastName, email, password } = req.body;

  // Filter the body to include only the allowed fields
  const filteredBody = filterObject(req.body, "firstName", "lastName", "email", "password");

  const existingUser = await User.findOne({ email: email });

  // If user exists and is verified, reject registration
  if (existingUser && existingUser.verified) {
    res.status(400).json({
      status: "error",
      message: "Email is already registered, please login",
    });
  } else if (existingUser) {
    // Update the existing unverified user
    await User.findOneAndUpdate({ email: email }, filteredBody, {
      new: true,
      validateModifiedOnly: true,
    });
    req.userId = existingUser._id;
    next();
  } else {
    // Create a new user
    const newUser = await User.create(filteredBody);
    req.userId = newUser._id;
    next();

    res.status(200).json({
      status: "success",
      message: "User registered successfully",
    });
  }
};

// Send a one-time password (OTP) to the user
exports.sendOTP = async (req, res, next) => {
  const { userId } = req;

  // Generate a 6-digit OTP without special characters
  const new_otp = otpGenerator.generate(6, {
    upperCaseAlphabets: false,
    lowerCaseAlphabets: false,
    specialChars: false,
  });

  // Set OTP expiry time (10 minutes from now)
  const otp_expiry_time = Date.now() + 10 * 60 * 1000;

  // Update the user's OTP and expiry time
  await User.findByIdAndUpdate(userId, {
    otp: new_otp,
    otp_expiry_time,
  });

  res.status(200).json({
    status: "success",
    message: "OTP sent successfully",
  });
};

// Verify the OTP provided by the user
exports.verifyOTP = async (req, res, next) => {
  const { email, otp } = req.body;

  const user = await User.findOne({
    email: email,
    otp_expiry_time: { $gt: Date.now() }, // Ensure OTP has not expired
  });

  if (!user) {
    res.status(400).json({
      status: "error",
      message: "Email is invalid or OTP expired",
    });
  }

  if (!(await user.correctOTP(otp, user.otp))) {
    res.status(400).json({
      status: "error",
      message: "Invalid OTP",
    });
  }

  user.verified = true; // Mark the user as verified
  user.otp = undefined; // Clear the OTP

  await user.save({ new: true, validateBeforeSave: true });

  const token = signToken(user._id);

  res.status(200).json({
    status: "success",
    message: "OTP verified successfully",
    token,
  });
};

// User login
exports.login = async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({
      status: "error",
      message: "Both email and password are required",
    });
    return;
  }

  const userDoc = await User.findOne({ email: email }).select("+password");

  if (!userDoc || !(await userDoc.correctPassword(password, userDoc.password))) {
    res.status(400).json({
      status: "error",
      message: "Email or password is incorrect",
    });
    return;
  }

  const token = signToken(userDoc._id);

  res.status(200).json({
    status: "success",
    message: "Logged in successfully",
    token,
  });
};

// Middleware to protect routes
exports.protect = async (req, res, next) => {
  let token;

  // Extract token from headers or cookies
  if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  } else {
    res.status(400).json({
      status: "error",
      message: "You are not logged in, please login to get access",
    });
    return;
  }

  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  const this_user = await User.findById(decoded.userId);

  if (!this_user) {
    res.status(400).json({
      status: "error",
      message: "The user doesn't exist",
    });
    return;
  }

  if (this_user.changedPasswordAfter(decoded.iat)) {
    res.status(400).json({
      status: "error",
      message: "User recently updated password, please login again",
    });
    return;
  }

  req.user = this_user;
  next();
};

// Handle forgotten password
exports.forgetPassword = async (req, res, next) => {
  const { email } = req.body;

  const user = await User.findOne({ email: email });

  if (!user) {
    res.status(400).json({
      status: "error",
      message: "There is no user with the given email address",
    });
    return;
  }

  const resetToken = user.createPasswordResetToken();

  const resetURL = `https://tawk.com/auth/resetPassword/?code=${resetToken}`;

  try {
    res.status(200).json({
      status: "success",
      message: "Password reset link sent to email",
    });
  } catch (error) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save({ validateBeforeSave: false });

    res.status(500).json({
      status: "error",
      message: "There was an error sending an email, please try again",
    });
  }
};

// Reset the user's password
exports.resetPassword = async (req, res, next) => {
  const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    res.status(400).json({
      status: "error",
      message: "Token is invalid or expired",
    });
    return;
  }

  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

  await user.save();

  const token = signToken(user._id);

  res.status(200).json({
    status: "success",
    message: "Password reset successfully",
    token,
  });
};
