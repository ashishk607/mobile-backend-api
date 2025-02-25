import mongoose, {Schema} from "mongoose";
import jwt from "jsonwebtoken";
import bcript from "bcrypt";

const userSchema =  new Schema(
    {
        fullName: {
            type: String,
            require: true,
            trim: true,
            lowecase: true
        },        
        email: {
            type: String,
            lowecase: true,
            trim: true
        },
        mobileNo: {
            type: String,
            required: true,
        },       
        password: {
            type: String,
            require: [true, 'Password is required'],
            minLength: [6, "Password must have at least 6 characters."],
            maxLength: [12, "Password cannot have more than 12 characters."],
        },
        avatar: {
            type: String, // cloudiary url
            default: null
            
        },
        college: {
            type: Schema.Types.ObjectId,
            ref: "Colleges"
        },
        course: {
            type: Schema.Types.ObjectId,
            ref: "Courses"
        },
        refreshToken: {
            type: String,
        },
        accountVerified: { 
            type: Boolean, 
            default: false 
        },
        verificationCode: {
            type: Number,
        },
        verificationCodeExpire: {
            type: Date,
        },
    }, 
    {
        timestamps: true
    }
);

// Hash password before saving
userSchema.pre("save", async function (next) {
    if(!this.isModified("password"))return next();
    this.password = await bcript.hash(this.password, 10)
    next();
});
// Compare password
userSchema.methods.isPasswordCorrect = async function(password){
    return await bcript.compare(password, this.password)
}
// Generate a 6-digit verification code
userSchema.methods.generateVerificationCode = function () {
    const verificationCode = Math.floor(100000 + Math.random() * 900000); // Ensures 6-digit number
    this.verificationCode = verificationCode;
    this.verificationCodeExpire = Date.now() + 10 * 60 * 1000; // Expires in 10 minutes
    return verificationCode;
};

userSchema.methods.generateAccessToken = function(){
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            mobileNo: this.mobileNo,
            fullName: this.fullName
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}
userSchema.methods.generateRefreshToken = function(){
    return jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}
export const User = mongoose.model("User", userSchema)