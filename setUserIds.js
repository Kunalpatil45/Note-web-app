const mongoose = require('mongoose');
const User = require('./models/User'); // path to your User model
require('dotenv').config();

mongoose.connect(process.env.MONGO_URI)
  .then(async () => {
    console.log("MongoDB connected!");
    console.log("Setting userIds for users without one...");

// Function to generate userId based on name
async function generateUserId(name) {
  const baseId = name.toLowerCase().replace(/\s+/g, "");
  const randomNum = Math.floor(1000 + Math.random() * 9000);
  let userId = `${baseId}${randomNum}`;

  // Ensure uniqueness
  const existingUser = await User.findOne({ userId });
  if (existingUser) {
    userId = `${baseId}${Date.now().toString().slice(-4)}`;
  }

  return userId;
}


    const users = await User.find({ userId: { $exists: false } }); // users without userId

    for (const user of users) {
      const userId = await generateUserId(user.name);
      user.userId = userId;
      await user.save();
      console.log(`Set userId for ${user.name}: ${userId}`);
    }

    console.log("All missing userIds have been set!");
    process.exit(0);
  })
  .catch(err => console.error(err));
