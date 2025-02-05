import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import sendEmail from "../utils/sendEmail.js";
import jwt from "jsonwebtoken";
import twilio from "twilio";

const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

const generateAccessAndRefreshTokens = async(userId) => {
    try {
        const user = await User.findById(userId);
        if (!user) throw new ApiError(404, "User not found");

        const refreshToken = user.generateRefreshToken();
        const accessToken = user.generateAccessToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken };

    } catch (error){
        throw new ApiError(500, "Error generating access and refresh tokens");
    }
};

//user registration code
const registerUser = asyncHandler( async (req, res) => {    
    const {fullName, email, mobileNo, password, verificationMethod} = req.body;

    if (!fullName || !email || !mobileNo || !password || !verificationMethod) {
        throw new ApiError(400, "All fields are required.");
    }

    if (!/^\+91\d{10}$/.test(mobileNo)) {
        throw new ApiError(400, "Invalid phone number format");
    }
    const existingUser = await User.findOne({
        $or: [{ email, accountVerified: true }, { mobileNo, accountVerified: true }],
    });

    if (existingUser) {
        throw new ApiError(409, "User with this mobile number already exists");
    }
    //profile image
    let avatar = null;
    if (req.files?.avatar?.[0]?.path) {
        avatar = await uploadOnCloudinary(req.files.avatar[0].path);
        if (!avatar) throw new ApiError(400, "Failed to upload avatar");
    }
  
    if (await User.countDocuments({ $or: [{ mobileNo, accountVerified: false }, { email, accountVerified: false }] }) > 3) {
        throw new ApiError(400, "Too many registration attempts. Try again later.");
    }
    const userData = {
        fullName,
        email,
        mobileNo,
        password,
        avatar: avatar?.url || null,
    };

    const user = await User.create(userData);

    const verificationCode = await user.generateVerificationCode();
    await user.save();
    sendVerificationCode(verificationMethod, verificationCode, fullName, email, mobileNo, res);
});

async function sendVerificationCode(verificationMethod, verificationCode, name, email, phone, res) {
    try {
        if (verificationMethod === "email") {
            const message = generateEmailTemplate(verificationCode, name);
            sendEmail({ email, subject: "Your Verification Code", message });
            res.status(200).json({
                success: true,
                message: `Verification email successfully sent to ${name}`,
            });
        } 
        else if (verificationMethod === "phone") {            
            await client.messages.create({
                body: `Your verification code is: ${verificationCode}`,
                from: process.env.TWILIO_PHONE_NUMBER,
                to: phone,
            });
        
            res.status(200).json({
                success: true,
                message: `OTP sent via SMS.`,
            });

        } 
        else {
            return res.status(500).json({
                success: false,
                message: "Invalid verification method.",
            });
        }
    } catch (error) {
      console.log(error);
      return res.status(500).json({
        success: false,
        message: "Verification code failed to send.",
      });
    }
}
function generateEmailTemplate(verificationCode, name) {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px; background-color: #f9f9f9;">
        <h2 style="color: #4CAF50; text-align: center;">Verification Code</h2>
        <p style="font-size: 16px; color: #333;">Dear ${name},</p>
        <p style="font-size: 16px; color: #333;">Your verification code is:</p>
        <div style="text-align: center; margin: 20px 0;">
          <span style="display: inline-block; font-size: 24px; font-weight: bold; color: #4CAF50; padding: 10px 20px; border: 1px solid #4CAF50; border-radius: 5px; background-color: #e8f5e9;">
            ${verificationCode}
          </span>
        </div>
        <p style="font-size: 16px; color: #333;">Please use this code to verify your email address. The code will expire in 10 minutes.</p>
        <p style="font-size: 16px; color: #333;">If you did not request this, please ignore this email.</p>
        <footer style="margin-top: 20px; text-align: center; font-size: 14px; color: #999;">
          <p>Thank you,<br>edupulse Team</p>
          <p style="font-size: 12px; color: #aaa;">This is an automated message. Please do not reply to this email.</p>
        </footer>
      </div>
    `;
}

const verifyOTP = asyncHandler(async (req, res, next) => {
    const { email, otp, mobileNo } = req.body;
  
    if (!/^\+91\d{10}$/.test(mobileNo)) {
        throw new ApiError(400, "Invalid phone number format");
    }
    const userEntries = await User.find({
        $or: [{ email, accountVerified: false }, { mobileNo, accountVerified: false }],
    }).sort({ createdAt: -1 });

    if (!userEntries.length) {
        throw new ApiError(404, "User not found");
    }

    const user = userEntries[0];

    if (userEntries.length > 1) {
        await User.deleteMany({ 
            _id: { $ne: user._id }, 
            $or: [
                { mobileNo, accountVerified: false }, 
                { email, accountVerified: false }
            ] 
        });
    }

    if (user.verificationCode !== Number(otp) || Date.now() > user.verificationCodeExpire) {
        throw new ApiError(400, "Invalid or expired OTP");
    }

    user.accountVerified = true;
    user.verificationCode = null;
    user.verificationCodeExpire = null;
    await user.save({ validateModifiedOnly: true });

    // Directly generate and return access and refresh tokens
    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);

    // Send the response with the tokens    
    res.status(200).json(
        new ApiResponse(
            200,
            {
                user:{
                    id: user._id,
                    fullName: user.fullName,
                    email: user.email,
                    mobileNo: user.mobileNo,
                },
                accessToken, 
                refreshToken
            },
            "Account verified successfully"

        )
    )


});

//user login code
const loginUser = asyncHandler(async (req, res) => {
    const {email, password} = req.body
    if(!email) {
        throw new ApiError(400, "email is required");
    }
    if(!password) {
        throw new ApiError(400, "password is required");
    }
    const user = await User.findOne({ email });
    if (!user) {
        throw new ApiError (404, "User dose not exist");
    }
    const isPasswordValid = await user.isPasswordCorrect(password)
    if(!isPasswordValid) {
        throw new ApiError(401, "Invalid user credentials");
    }
    const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200,
            {
                user:loggedInUser,
                accessToken, 
                refreshToken
            },
            "User logged In Successfully"

        )
    )
});

const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: {
                refreshToken: 1
            }
        },
        {
            new: true
        }
    )
    const options = {
        httpOnly: true,
        secure: true
    }

    return res 
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"))
})

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookie.refreshToken || req.body.refreshAccessToken
    if (!incomingRefreshToken) {
        throw new ApiError(401, "unauthorized request")
    }
    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedToken?._id)
    
        if (!user) {
            throw new ApiError(401, "Invalid refresh token")
        }
    
        if (incomingRefreshToken !== user.refreshToken) {
            throw new ApiError(401, "refresh token is expired or used")
        }
        const options = {
            httpOnly: true,
            secure: true
        }
        const {accessToken, newRefreshToken} = await generateAccessAndRefereshTokens(user._id)
    
        return res
        .status(200)
        .clearCookie("accessToken",accessToken, options)
        .clearCookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200,
                {accessToken, refreshToken: newRefreshToken},
                "Access Token refresh successfully"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }

})

const changeCurrentPassword = asyncHandler(async(req, res) => {
    const {oldPassword, newPassword} = res.body

    const user = await User.findById(req.user?._id)
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if (!isPasswordCorrect) {
        throw new ApiError(400, "Invalid old password")
    }

    user.password = newPassword
    await user.save({validateBeforeSave: false})
    return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password change successfully"))
})

const getCurrentUser = asyncHandler(async (req, res) => {
    return res
    .status(200)
    .json(200, req.user, "current user fetched successfully")
})

const updateAccountDetails = asyncHandler(async (req, res) => {
    const {fullName, email} = req.body

    if(!fullName || !email) {
        throw new ApiError(400, "all fields are required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName,
                email
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200, user, "Account Details Updated successfully"))
})

const updateUserAvatar = asyncHandler(async (req, res) => {
    const avatarLocalPath = req.file?.path

    if(!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url) {
        throw new ApiError(400, "Error while uploading on avatar")
    }
    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {                
                avatar: avatar.url
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200, user, "avatar image Updated successfully"))
})

const getUserChannelProfile = asyncHandler(async (req, res) => {
    const {username} = req.params

    if(!username?.trim()) {
        throw new ApiError(400, "username is missing")         
    }
    const channel = await User.aggregate([
        {
            $match: {
                username: username?.toLowerCase()
            }
            
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "channel",
                as: "subscribers"
            }
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribedTo"
            }
        },
        {
            $addFields: {
                subscribersCount: {
                    $size: "$subscriber"
                },
                channelsSubscribedToCount: {
                    $size: "$subscribedTo"
                },
                isSubscribed: {
                    $cond: {
                        if: {$in: [req.user?._id, "$subscriber.subscriber"]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project: {
                fullName: 1,
                username: 1,
                subscribersCount: 1,
                channelsSubscribedToCount: 1,
                isSubscribed: 1,
                avatar: 1,
                email: 1
            }
        }
    ])
    console.log(channel)

    if (!channel?.length) {
        throw new ApiError(404, "channel dose not exists")
    }
    return res
    .status(200)
    .json(
        new ApiResponse(200, channel[0], "user channel fetched successfully")
    )
})



export {
    registerUser,
    verifyOTP,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    getUserChannelProfile
}