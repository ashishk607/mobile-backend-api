import mongoose, {Schema} from "mongoose";
const collegeSchema = new Schema(
    {
        name: {
            type: String,
            required: true,
            trim: true,
            lowercase: true
        },
        city: {
            type: String,
            required: true,
            trim: true,
            lowercase: true
        },
        state: {
            type: String,
            required: true,
            trim: true,
            lowercase: true
        },
        country: {
            type: String,
            required: true,
            trim: true,
            lowercase: true
        },
        courses: [
            {
                type: Schema.Types.ObjectId,
                ref: "Courses"
            }
        ]
    },
    {
        timestamps: true

    }
);
export default mongoose.model("Colleges", collegeSchema);