const jwt = require("jsonwebtoken");

function authMiddleware(req, res, next) {
  const token = req.cookies.token;   // requires cookie-parser
  if (!token) {
    return res.status(401).json({ error: "Not authorized" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secert_jwt_key");
    req.user = decoded; // add user info to request
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

module.exports = authMiddleware;
