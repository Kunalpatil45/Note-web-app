const jwt = require("jsonwebtoken");

function authMiddleware(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        res.redirect("/signup");
        return; // <- Ensure no further processing
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || "secret_jwt_key");
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ message: "Token invalid or expired" }); // <- JSON instead of redirect
    }
}

module.exports = authMiddleware;
