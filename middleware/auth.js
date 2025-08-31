const jwt = require("jsonwebtoken");

function authMiddleware(req, res, next) {
  const token = req.cookies.token;   // requires cookie-parser
  if (!token) {
    return res.redirect("/",);  // redirect instead of JSON
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secret_jwt_key");
    req.user = decoded; // add user info to request
    next();
  } catch (err) {
    return res.redirect("/");  // redirect if invalid/expired
  }
}

module.exports = authMiddleware;
