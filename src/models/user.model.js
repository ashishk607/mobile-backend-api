import mongoose, {Schema} from "mongoose";
import jwt from "jsonwebtoken";
import bcript from "bcrypt";

const userSchema =  new Schema(
    {
        fullName: {
            type: String,
            require: true,
            trim: true,
            index: true
        },        
        email: {
            type: String,
            require: true,
            unique: true,
            lowecase: true,
            trim: true
        },
        mobileNo: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            index: true,
            validate: {
                validator: function (v) {
                    return /^\d{10}$/.test(v);
                },
                message: props => `${props.value} is not a valid 10-digit mobile number!`
            }
        },       
        password: {
            type: String,
            require: [true, 'Password is required']
        },
        avatar: {
            type: String, // cloudiary url
            default: null
            
        },
        refreshToken: {
            type: String,
        }
    }, 
    {
        timestamps: true
    }
);
userSchema.pre("save", async function (next) {
    if(!this.isModified("password"))return next();

    this.password = await bcript.hash(this.password, 10)
    next();
}),
userSchema.methods.isPasswordCorrect = async function(password){
    return await bcript.compare(password, this.password)
}
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