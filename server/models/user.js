const mongoose = require("mongoose"); // Mongoose is used for MongoDB object modeling.
const bcrypt = require("bcrypt"); // bcrypt is used for hashing passwords and OTPs.
const crypto = require("crypto"); // crypto is used for generating secure tokens.

// Define the schema for a user
const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, "First Name is required"], // First name is required.
  },
  lastName: {
    type: String,
    required: [true, "Last Name is required"], // Last name is required.
  },
  avatar: {
    type: String, // Optional field for storing the user's avatar URL.
  },
  email: {
    type: String,
    required: [true, "Email is required"], // Email is required.
    validate: {
      // Custom validator for email format.
      validator: function (email) {
        return String(email)
          .toLowerCase()
          .match(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/);
      },
      message: (props) => `Email (${props.value}) is invalid!`, // Validation error message.
    },
  },
  password: {
    type: String, // User's hashed password.
  },
  passwordConfirm: {
    type: String, // Confirm password field to ensure both passwords match.
    validate: {
      validator: function (passwordConfirm) {
        return passwordConfirm === this.password; // Checks if passwords match.
      },
      message: "Passwords are not the same!", // Error message if passwords don't match.
    },
  },
  passwordChangedAt: {
    type: Date, // Timestamp for when the password was last changed.
  },
  passwordResetToken: {
    type: String, // Token for resetting the password.
  },
  passwordResetExpires: {
    type: Date, // Expiry time for the reset token.
  },
  createdAt: {
    type: Date, // User creation timestamp.
  },
  updatedAt: {
    type: Date, // User update timestamp.
  },
  otp: {
    type: Number, // One-time password (OTP).
  },
  otp_expiry_time: {
    type: Date, // Expiry time for the OTP.
  },
  verified: {
    type: Boolean,
    default: false, // Indicates if the user is verified.
  },
});

// Pre-save middleware for hashing the OTP before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("otp")) return next(); // Only hash the OTP if it is modified.
  this.otp = await bcrypt.hash(this.otp, 12); // Hash the OTP with a salt factor of 12.
  next();
});

// Pre-save middleware for hashing the password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next(); // Only hash the password if it is modified.
  this.password = await bcrypt.hash(this.password, 12); // Hash the password with a salt factor of 12.
  next();
});

// Method to check if the provided password matches the stored hashed password
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword); // Compare passwords.
};

// Method to check if the provided OTP matches the stored hashed OTP
userSchema.methods.correctOTP = async function (candidateOTP, userOTP) {
  return await bcrypt.compare(candidateOTP, userOTP); // Compare OTPs.
};

// Method to create a password reset token
userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex"); // Generate a random reset token.

  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex"); // Hash the reset token and store it.

  return resetToken; // Return the plain token (to send to the user).
};

// Method to check if the password was changed after a given JWT timestamp
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  return JWTTimestamp < this.passwordChangedAt; // Check if the password has changed since the token was issued.
};

// Create the User model from the schema
const User = new mongoose.model("User", userSchema);

// Export the User model for use in other files
module.exports = User;
