import mongoose,{Schema} from "mongoose";
const courseSchema = new Schema(
    {
        name: {
            type: String,
            required: true,
            trim: true,
            lowercase: true
        },
        duration: {
            type: Number,
            required: true
        },
        college: {
            type: Schema.Types.ObjectId,
            ref: "Colleges"
        }
    },
    {
        timestamps: true
    }
);
export default mongoose.model("Courses", courseSchema);