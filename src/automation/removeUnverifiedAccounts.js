import cron from "node-cron";
import { User } from "../models/user.model.js";

const removeUnverifiedAccounts = () => {
  cron.schedule("*/30 * * * *", async () => {
    try {
      console.log("Running scheduled job: Removing unverified accounts...");

      const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);

      const result = await User.deleteMany({
        accountVerified: false,
        createdAt: { $lt: thirtyMinutesAgo },
      });

      console.log(`Deleted ${result.deletedCount} unverified accounts.`);
    } catch (error) {
      console.error("Error in scheduled task (removeUnverifiedAccounts):", error.message);
    }
  });
};

export default removeUnverifiedAccounts;
