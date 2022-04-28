/**
 *
 * @author Paravada Naveen Teja <https://www.pnaveenteja.com/>
 * @version 1.0.0
 *
 * @description JWT token Operations
 *
 * @package jsonwebtoken to be installed
 *
 * @requires process.env.JWT_ALGO Signing Algorithm Type
 * @requires process.env.JWT_EXPIRY Expiry Time
 * @requires process.env.JWT_SECRET Secret Key Phase
 */

const jwt = require("jsonwebtoken");

/**
 * @description Generates JWT token
 * @param {Object} data JWT Payload
 * @returns encrypted token
 * @error Console Logs the error
 */

function generateJWTToken(data) {
  try {
    const token = jwt.sign(data, process.env.JWT_SECRET, {
      algorithm: process.env.JWT_ALGO,
      expiresIn: process.env.JWT_EXPIRY,
    });
    return token;
  } catch (error) {
    return console.error("jwtEncrypt : JWT Token cannot be created.", err);
  }
}

/**
 *
 * @param {Object} req Express Js Request
 * @param {Object} res Express JS respond
 * @param {Object} next express next function
 *
 * @returns Decoded Payload
 *
 * @error Console Logs the error
 *
 */
function verifyJWTToken(req, res) {
  try {
    const token = req.header("Authorization");
    if (!token) {
      return res.status(403).json({ status: 403, message: "Access denied." });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return decoded;
  } catch (error) {
    console.log("Invalid Token" + error);
  }
}

module.exports = {
  generateJWTToken,
  verifyJWTToken,
};
