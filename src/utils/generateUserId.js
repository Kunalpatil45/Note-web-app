const User = require('../models/User');

async function generateUserId(name) {
    let base = name.split(" ")[0].toLowerCase().replace(/[^a-z0-9]/g, "");
    let userId;
    let isUnique = false;

    while (!isUnique) {
        const randomNum = Math.floor(100 + Math.random() * 900);
        userId = `${base}${randomNum}`;

        const existingUser = await User.findOne({ userId });
        if (!existingUser) {
            isUnique = true;
        }
    }
    return userId;
}

module.exports = generateUserId;
