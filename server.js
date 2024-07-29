const dotenv = require("dotenv");
dotenv.config();
const express = require("express");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");
const mongoose = require("mongoose");
const {
  User,
  Job,
  Admin,
  Payment,
  Mentor,
  Review,
  Webinar,
} = require("./schema");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");
// const router = require("./routes/paymentRoutes");
const cloudinary = require("cloudinary");
const { v2: cloud } = require("cloudinary");
const bodyParser = require("body-parser");
const fileUpload = require("express-fileupload");
const crypto = require("crypto");
const cron = require("node-cron");
// const OpenAIApi = require('openai');
// Initialize cors
const app = express();
const axios = require("axios");
const uniqid = require("uniqid");
const sha256 = require("sha256");
const streamifier = require('streamifier');
const Jimp = require("jimp");

app.use(cors("*"));

let MENTORVALIDITY = 0;

app.use(morgan("dev"));
app.use(bodyParser.json({ limit: "50mb" }));
app.use(
  bodyParser.urlencoded({
    limit: "50mb",
    extended: true,
    parameterLimit: 5000000,
  })
);
app.use(express.json());
app.use(fileUpload());
const { google } = require("googleapis");

// Connect to MongoDB Atlas
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("Connected to MongoDB Atlas");
  })
  .catch((err) => {
    console.error("Error connecting to MongoDB Atlas:", err.message);
  });

cloudinary.v2.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Express session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Google OAuth 2.0 configuration
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://sample-server-sand.vercel.app/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;
        const name = profile.displayName;
        const profilephoto = profile.photos[0].value;

        // Check if user already exists
        let user = await User.findOne({ email: email });
        if (!user) {
          // If user doesn't exist, create a new one
          user = new User({
            email: email,
            name: name,
            jobs: [],
            accessToken: accessToken,
            profilephoto: {
              public_id: "1234",
              url: profilephoto,
            },
          });
          await user.save();
        } else {
          // If user exists, update their accessToken and profile photo
          user.accessToken = accessToken;
          user.profilephoto = {
            public_id: "1234",
            url: user.profilephoto.url,
          };
          await user.save();
        }
        done(null, user);
      } catch (error) {
        console.error("Error saving user details to database:", error);
        done(error, null);
      }
    }
  )
);

// Serialize user
passport.serializeUser((user, done) => {
  done(null, user);
});

// Deserialize user
passport.deserializeUser((user, done) => {
  done(null, user);
});

// Routes
app.get("/", (req, res) => {
  res.send("Home Page");
});

// Google auth route
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Google auth callback route
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    // Successful authentication, redirect to home page or handle as needed
    res.redirect(
      `${process.env.FRONTEND_URL}/?email=${req.user.email}&name=${req.user.name}&accessToken=${req.user.accessToken}`
    );
  }
);

// Logout route
app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

// APIs
app.post("/addJob", async (req, res) => {
  try {
    let user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).send("User not found");
    }
    const job = req.body;

    job.imageLink = user.profilephoto.url;
    job.userName = user.name;

    const newJob = await Job(job);

    user.jobs.push(newJob._id);

    await user.save();
    await newJob.save();
    res.send(newJob);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.get("/getJobs", async (req, res) => {
  try {
    const jobs = await Job.find();
    res.send(jobs);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.get("/getUser/:email", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.params.email });
    res.status(200).send(user);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.get("/premiumCheck/:email", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.params.email });
    if (user) {
      res.status(200).send(user.isPremium);
    } else {
      res.status(404).send("User not found.");
    }
  } catch (error) {
    res.status(500).send(error);
  }
});

app.get("/getUsers", async (req, res) => {
  try {
    const users = await User.find();
    res.send(users);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.post("/updateUser/:email", async (req, res) => {
  try {
    const user = await User.findOneAndUpdate(
      { email: req.params.email },
      { $set: { isPremium: req.body.isPremium } },
      { new: true }
    );

    if (!user) {
      return res.status(404).send("User not found");
    }

    res.send(user);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.get("/getJobs/:email", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.params.email });
    if (!user) {
      return res.status(404).send("User not found");
    }
    let jobs = [];
    for (let i = 0; i < user.jobs.length; i++) {
      const job = await Job.findOne({ _id: user.jobs[i] });
      jobs.push(job);
    }

    res.send(jobs);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.delete("/deleteJob/:jobId", async (req, res) => {
  try {
    const job = await Job.findOneAndDelete({ _id: req.params.jobId });
    if (!job) {
      return res.status(404).send("Job not found");
    }

    const user = await User.findOne({ email: job.email });
    if (!user) {
      return res.status(404).send("User not found");
    }

    // Remove job from user's jobs array
    user.jobs = user.jobs.filter(
      (jobId) => jobId.toString() !== req.params.jobId
    );

    await user.save();

    res.send(job);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = await Admin.findOne({ email });

    if (!admin) {
      return res.send({ message: "Admin not found" });
    }

    if (admin.password !== password) {
      return res.send({ message: "Invalid password" });
    }

    const token = jwt.sign({ email }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.send({ message: "Login successful", token });
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).send("Server error");
  }
});

app.post("/updateUserInfo/:email", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.params.email });
    if (!user) {
      return res.status(404).send("User not found");
    }
    user.linkedin = req.body.linkedin;
    user.github = req.body.github;
    user.phoneNumber = req.body.phoneNumber;
    user.whatsappNumber = req.body.whatsappNumber;
    user.bio = req.body.bio;
    await user.save();
    res.send(user);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.post("/editUserData/:email", async (req, res) => {
  const { userData, imageChange } = req.body;
  try {
    const user = await User.findOne({ email: req.params.email });
    if (!user) {
      return res.status(404).send("User not found");
    }

    if (imageChange) {
      const imageId = user.profilephoto ? user.profilephoto.public_id : null;

      // Check if there's an existing image to delete
      if (imageId !== "1234") {
        try {
          await cloudinary.uploader.destroy(imageId);
        } catch (cloudinaryError) {
          console.error(
            "Error deleting previous profile photo:",
            cloudinaryError
          );
        }
      }

      try {
        const newPic = await cloudinary.uploader.upload(
          userData.profilephoto.url,
          {
            folder: "LearnDuke",
            width: 150,
            crop: "scale",
          }
        );

        userData.profilephoto = {
          public_id: newPic.public_id,
          url: newPic.secure_url,
        };
      } catch (uploadError) {
        console.error("Error uploading new profile photo:", uploadError);
        return res.status(500).send("Error uploading profile photo");
      }
    }

    // Update the user fields that are present in the request body
    Object.keys(userData).forEach((key) => {
      user[key] = userData[key];
    });

    // Save the updated user
    await user.save();

    res.status(200).send("User data updated successfully");
  } catch (error) {
    console.error("Error updating user data:", error);
    res.status(500).send("Internal server error");
  }
});

// get job by id
app.get("/getJobById/:jobId", async (req, res) => {
  try {
    const job = await Job.findOne({ _id: req.params.jobId });
    if (!job) {
      return res.status(404).send("Job not found");
    }
    res.send(job);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.get("/getSimilarJobs/:jobId", async (req, res) => {
  try {
    const jobId = req.params.jobId;

    // Fetch the current job by its ID
    const currjob = await Job.findById(jobId);
    if (!currjob) {
      return res.status(404).send("Job not found");
    }

    const tags = currjob.tags;
    if (!tags || tags.length === 0) {
      return res.status(404).send("No similar jobs found");
    }

    // Find jobs with at least one matching tag, excluding the current job
    const similarJobs = await Job.find({
      _id: { $ne: currjob._id },
      tags: { $in: tags },
    });

    res.send(similarJobs);
  } catch (error) {
    console.error("Error fetching similar jobs:", error);
    res.status(500).send(error);
  }
});

const checkExpiringSubscritions = async () => {
  const payments = await Payment.find({ expirationDate: new Date() });
  payments.forEach(async (payment) => {
    const user = await User.findOne({ email: payment.user });
    user.isPremium = false;
    await user.save();
  });
};

cron.schedule("0 0 * * *", () => {
  checkExpiringSubscritions();
  checkingMentorValidity();
});

const checkingMentorValidity = async () => {
  const mentors = await Mentor.find();
  const date = new Date();
  mentors.forEach(async (mentor) => {
    const payments = await Payment.find({ user: mentor.email });
    payments.forEach(async (payment) => {
      const date1 = new Date(payment.expirationDate);
      date1.setDate(date1.getDate() + 1);
      if (date1 < date) {
        mentor.plans.map((plan, index) => {
          if (plan === payment.plan && plan !== "Lifetime") {
            mentor.plans.splice(index, 1);
            mentor.isPremium = false;
          }
        });
        await mentor.save();
      }
    });
  });
};

cron.schedule("* * * * *", async () => {
  // now i need to get data of how many jobs have been posted on different domanins
  // and then send the email to the user

  // create a dictionary of domain and count
  const domainCount = {};
  const jobs = await Job.find({ isReviewed: true });
  // jobs posted only today
  const today = new Date();
  const todayJobs = jobs.filter(
    (job) => job.postedOn.getDate() === today.getDate()
  );
  todayJobs.forEach((job) => {
    if (domainCount[job.domain]) {
      domainCount[job.domain] += 1;
    } else {
      domainCount[job.domain] = 1;
    }
  });

  const users = await User.find();
  users.forEach(async (user) => {
    if (user.jobAllerts) {
      const email = user.email;
      let message = "Hi, here are the job alerts for today:\n\n";
      Object.keys(domainCount).forEach((domain) => {
        message += `${domain}: ${domainCount[domain]} jobs\n`;
      });
    }
  });
});

app.post("/jobAlerts/:email", async (req, res) => {
  try {
    const email = req.params.email;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).send("User not found");
    }
    user.jobAllerts = req.body.jobAlerts;
    await user.save();
    res.send(user);
  } catch (error) {
    res.status(500, error);
  }
});

app.get("/getReviewedJobs", async (req, res) => {
  try {
    const {
      title,
      location,
      jobType,
      domain,
      education,
      page = 1,
      limit = 8,
    } = req.query;

    let query = {};
    if (title) {
      query.title = { $regex: new RegExp(title, "i") };
    }
    if (typeof location === "string" && location.trim() !== "") {
      query.location = { $regex: new RegExp(location.trim(), "i") };
    }
    if (typeof jobType === "string" && jobType.trim() !== "") {
      query.jobType = { $regex: new RegExp(jobType.trim(), "i") };
    }
    query.isReviewed = true;

    const orConditions = [];

    if (domain) {
      orConditions.push(...domain.map((d) => ({ domain: d })));
    }
    if (education) {
      orConditions.push(...education.map((e) => ({ education: e })));
    }

    // If there are any $or conditions, add them to the query
    if (orConditions.length > 0) {
      query.$or = orConditions;
    }

    try {
      const jobs = await Job.find(query)
        .sort({ postedOn: -1 })
        .skip((page - 1) * limit)
        .limit(parseInt(limit));
      const totalJobs = await Job.countDocuments(query);

      res.status(200).json({
        jobs,
        totalJobs,
        totalPages: Math.ceil(totalJobs / limit),
        currentPage: parseInt(page),
      });
    } catch (error) {
      console.error("Error fetching jobs:", error);
      res.status(500).send("Error fetching jobs");
    }
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).send("Server error");
  }
});

app.post("/undoReview/:jobId", async (req, res) => {
  try {
    const job = await Job.findOneAndUpdate(
      { _id: req.params.jobId },
      { $set: { isReviewed: false } },
      { new: true }
    );

    if (!job) {
      return res.status(404).send("Job not found");
    }

    res.send(job);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.post("/rejectJob/:jobId", async (req, res) => {
  try {
    const job = await Job.findOneAndUpdate(
      { _id: req.params.jobId },
      { $set: { isRejected: true } },
      { new: true }
    );

    if (!job) {
      return res.status(404).send("Job not found");
    }

    res.send(job);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.post("/approveJob/:jobId", async (req, res) => {
  try {
    const job = await Job.findOneAndUpdate(
      { _id: req.params.jobId },
      { $set: { isReviewed: true } },
      { new: true }
    );

    if (!job) {
      return res.status(404).send("Job not found");
    }

    res.send(job);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.post("/undoReject/:jobId", async (req, res) => {
  try {
    const job = await Job.findOneAndUpdate(
      { _id: req.params.jobId },
      { $set: { isRejected: false } },
      { new: true }
    );

    if (!job) {
      return res.status(404).send("Job not found");
    }

    res.send(job);
  } catch (error) {
    res.status(500).send(error);
  }
});

// emails section

app.post("/sendEmail", async (req, res) => {
  try {
    const { to, subject, text } = req.body;
    const mailOptions = {
      from: process.env.EMAIL,
      to,
      subject,
      text,
    };

    await transporter.sendMail(mailOptions);
    res.send("Email sent successfully");
  } catch (error) {
    console.error("Error sending email:", error);
    res.status(500).send("Internal server error");
  }
});

app.get("/getSubscriptions/:email", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.params.email });
    if (!user) {
      return res.status(404).send("User not found");
    }
    const subscriptions = user.payments;
    const allPayments = [];
    for (let i = 0; i < subscriptions.length; i++) {
      const payment = await Payment.findOne({ _id: subscriptions[i] });
      allPayments.push(payment);
    }
    res.send(allPayments); // Send the allPayments array
  } catch (error) {
    res.status(500).send(error);
  }
});

// mentors section

app.post("/addMentor/:email", async (req, res) => {
  try {
    let user = await User.findOne({ email: req.params.email });
    if (!user) {
      return res.status(404).send("User not found");
    }
    let mentorData = await req.body;

    //cloudinary image
    try {
      const newPic = await cloudinary.uploader.upload(mentorData.profilePhoto, {
        folder: "LearnDuke",
        width: 150,
        crop: "scale",
      });

      mentorData.profilePhoto = {
        public_id: newPic.public_id,
        url: newPic.secure_url,
      };
    } catch (uploadError) {
      console.log("Error uploading new profile photo:", uploadError);
    }
    const mentorDataWithEmail = {
      ...mentorData,
      email: user.email,
      name: user.name,
    };
    const mentor = new Mentor(mentorDataWithEmail);
    await mentor.save();
    res.send(mentor);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.get("/getMentors", async (req, res) => {
  try {
    const mentors = await Mentor.find({ isPremium: true });
    if (!mentors) {
      res.status(201).send("No mentors found");
    }
    // const mentorsWithUserDetails = [];
    // for (const mentor of mentors) {
    //   try {
    //     const user = await User.findOne({ email: mentor.email });
    //     if (!user) {
    //       console.warn(`User not found for mentor with email: ${mentor.email}`);
    //     } else {
    //       // Create a new object by spreading mentor data and adding name and isPremium properties
    //       const mentorWithUserDetails = {
    //         ...mentor.toObject(), // Convert Mongoose document to plain JavaScript object
    //         name: user.name,
    //         isPremium: user.isPremium,
    //       };
    //       mentorsWithUserDetails.push(mentorWithUserDetails);
    //     }
    //   } catch (error) {
    //     console.error("Error fetching user for mentor:", error);
    //   }
    // }

    res.send(mentors);
  } catch (error) {
    console.error("Error fetching mentors:", error);
    res.status(500).send(error);
  }
});

app.get("/getMentorsAdmin", async (req, res) => {
  try {
    const mentors = await Mentor.find().sort({ postedOn: -1 });
    if (!mentors) {
      res.status(201).send("No mentors found");
    }
    res.send(mentors);
  } catch (error) {
    console.error("Error fetching mentors:", error);
    res.status(500).send(error);
  }
});

app.get("/updateMentorViaAdmin", async(req,res) => {
  try {
    const mentor = await Mentor.findById(req.query.id)

    mentor.isPremium = true;
    mentor.plans.push(req.query.plan)

    await mentor.save();
    res.status(200).send("Payment Updated Successfully.")

  }catch(error){
    res.status(500).send("Internal server error")
  }
})

app.get("/getMentor/:id", async (req, res) => {
  try {
    const mentor = await Mentor.findOne({ _id: req.params.id });
    if (!mentor) {
      return res.status(404).send("Mentor not found");
    }

    // Get reviews of mentor
    const reviewsPromises = mentor.reviews.map((reviewId) =>
      Review.findOne({ _id: reviewId })
    );
    const reviews = await Promise.all(reviewsPromises);

    // Get data from user
    const user = await User.findOne({ email: mentor.email });
    if (!user) {
      return res.status(404).send("User not found");
    }

    // Append data of user into mentor object
    const mentorWithUserDetails = {
      ...mentor.toObject(),
      name: user.name,
      isPremium: user.isPremium,
      jobs: user.jobs,
      linkedin: user.linkedin,
      github: user.github,
      bio: user.bio,
      payments: user.payments,
      plans: user.plans,
      jobAllerts: user.jobAllerts,
      reviews: reviews,
    };

    res.send(mentorWithUserDetails);
  } catch (error) {
    console.error("Error fetching mentor data:", error); // Log the error for debugging
    res.status(500).send("An error occurred while fetching mentor data.");
  }
});

app.get("/isAlreadyMentor/:email", async (req, res) => {
  try {
    const mentor = await Mentor.findOne({ email: req.params.email });
    if (mentor) {
      res.json({ success: true, mentor });
    } else {
      res.send(false);
    }
  } catch (error) {
    res.status(500).send(error);
  }
});

app.put("/updateMentor/:email", async (req, res) => {
  try {
    const mentor = await Mentor.findOne({ email: req.params.email });
    if (!mentor) {
      return res.status(404).send("Mentor not found");
    }

    // if type of res.body.profilePhoto is string then upload the image to cloudinary and destroy previous image
    if (typeof req.body.profilePhoto == "string") {
      const imageId = mentor.profilePhoto
        ? mentor.profilePhoto.public_id
        : null;

      // Check if there's an existing image to delete
      if (imageId && imageId !== "1234") {
        try {
          await cloudinary.uploader.destroy(imageId);
        } catch (cloudinaryError) {
          console.error(
            "Error deleting previous profile photo:",
            cloudinaryError
          );
        }
      }

      try {
        const newPic = await cloudinary.uploader.upload(req.body.profilePhoto, {
          folder: "LearnDuke",
          width: 150,
          crop: "scale",
        });

        req.body.profilePhoto = {
          public_id: newPic.public_id,
          url: newPic.secure_url,
        };
      } catch (uploadError) {
        console.error("Error uploading new profile photo:", uploadError);
        return res.status(500).send("Error uploading profile photo");
      }
    }

    const newMentor = await Mentor.findByIdAndUpdate(mentor._id, req.body, {
      new: true,
      runValidators: true,
      useFindAndModify: false,
    });

    await mentor.save();
    res.send(newMentor);
  } catch (error) {
    res.status(500).send(error);
  }
});

app.get("/getMentor", async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const startIndex = (page - 1) * limit;

  const search = req.query.search || "";
  const domain = req.query.domain || "All Domains";
  const subDomains = req.query.subDomain ? req.query.subDomain.split(",") : [];

  try {
    // Construct query conditionally

    let query = {};

    if (search) {
      query = {
        $or: [
          { name: { $regex: new RegExp(search, "i") } },
          { domain: { $regex: new RegExp(search, "i") } },
          { subDomain: { $elemMatch: { $in: [new RegExp(search, "i")] } } },
          { skills: { $elemMatch: { $in: [new RegExp(search, "i")] } } },
        ],
      };
    }

    if (domain !== "All Domains") {
      query.domain = { $regex: new RegExp(domain, "i") };
    }

    if (subDomains.length > 0) {
      query.subDomain = {
        $elemMatch: { $in: subDomains.map((sub) => new RegExp(sub, "i")) },
      };
    }

    // const totalMentors = await Mentor.countDocuments(query).exec();
    const mentors = await Mentor.find(query)
      .sort({ postedOn: -1 })
      .limit(limit)
      .skip(startIndex)
      .exec();

    const premiummentor = mentors.filter((mentor) => mentor.isPremium === true);

    const totalMentor = await Mentor.countDocuments(query);
    const totalPages = Math.ceil(totalMentor/limit);

    res.send({
      startIndex,
      totalmentor: totalMentor,
      totalPages,
      mentors: premiummentor.filter(Boolean), // Filter out null or undefined values
    });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

//redirect api after phonepe payment
app.get(
  "/redirect-url/:merchantTransactionId/:name/:days/:mail/:isMentor",
  async (req, res) => {
    const {
      merchantTransactionId,
      name,
      days,
      mail,
      isMentor,
      //  isMentor, user,
    } = req.params;

    const user = await User.findOne({ email: mail });
    if (merchantTransactionId) {
      const xVerify =
        sha256(
          `/pg/v1/status/${process.env.PHONE_PE_MERCHANT_ID}/${merchantTransactionId}${process.env.PHONE_PE_SALT_KEY}`
        ) +
        "###" +
        process.env.PHONE_PE_SALT_INDEX;

      const options = {
        method: "get",
        url: `${process.env.PHONE_PE_HOST_URL}/pg/v1/status/${process.env.PHONE_PE_MERCHANT_ID}/${merchantTransactionId}`,
        headers: {
          accept: "application/json",
          "Content-Type": "application/json",
          "X-MERCHANT-ID": merchantTransactionId,
          "X-VERIFY": xVerify,
        },
      };
      axios
        .request(options)
        .then(async function (response) {
          const paymentDate = new Date();
          const expirationDate = new Date();
          expirationDate.setDate(expirationDate.getDate() + parseInt(days));

          const paymentDetails = {
            paymentDate: paymentDate,
            plan: name,
            amount: parseInt(response.data?.data.amount) / 100,
            status: response.data?.code,
            user: mail,
            transactionId: response.data?.data.transactionId,
            merchantTransactionId: merchantTransactionId,
            expirationDate: expirationDate,
            paymentMethod: response.data?.data?.paymentInstrument.type,
            pgTransactionId:
              response.data?.data?.paymentInstrument.pgTransactionId,
            arn: response.data?.data.paymentInstrument.arn,
          };
          const payment = new Payment(paymentDetails);
          try {
            await payment.save();
          } catch (error) {
            console.error("Error saving payment:", error);
            // Handle the error appropriately
          }
          // console.log(payment)
          if (response.data.code === "PAYMENT_SUCCESS") {
            if (isMentor == "true") {
              const mentor = await Mentor.findOne({ email: user.email });
              if (!mentor) {
                return res.status(404).send("Mentor not found");
              }
              if (MENTORVALIDITY < 20000 && payment.plan === "Premium") {
                mentor.plans.push("Lifetime");
                MENTORVALIDITY += 1;
              } else {
                mentor.plans.push(payment.plan);
              }
              mentor.payments.push(payment._id);
              mentor.isPremium = true;
              await payment.save();
              await mentor.save();
            } else {
              user.plans.push(payment.plan);
              user.payments.push(payment._id);
              user.isPremium = true;
              await user.save();
            }
            res.redirect(
              `${process.env.FRONTEND_URL}/paymentsuccess`
            );
          } else if (response.data.code === "PAYMENT_ERROR") {
            res.redirect(`${process.env.FRONTEND_URL}/paymentfailed`);
          }
        })
        .catch(function (error) {
          res.redirect(`${process.env.FRONTEND_URL}/paymentfailed`);
        });
    } else {
      res.redirect(`${process.env.FRONTEND_URL}/paymentfailed`);
    }
  }
);

app.get("/pay/:name/:mail/:isMentor", async (req, res) => {
  const plans = [
    {
      name: "Basic",
      price: 99, // in INR
      days: 30,
      isMentor: "true",
    },
    {
      name: "Advance",
      price: 149, // in INR
      days: 100,
      isMentor: "true",
    },
    {
      name: "Premium",
      price: 399,
      days: 365,
      isMentor: "true",
    },
    {
      name: "Basic",
      price: 99, // in INR
      days: 100,
      isMentor: "false",
    },
    {
      name: "Advance",
      price: 399, // in INR
      days: 365,
      isMentor: "false",
    },
    {
      name: "Premium",
      price: 999, // in INR
      days: 180,
      isMentor: "false",
    },
    {
      name: "Teacher Pro",
      price: 399, // in INR
      days: 100,
      isMentor: "false",
    },
  ];

  const { name, mail, isMentor } = req.params;

  const plan = plans.find(
    (plan) => plan.name === name && plan.isMentor === isMentor
  );

  if (!plan) {
    res
      .status(404)
      .redirect(`${process.env.FRONTEND_URL}/paymentfailed`);
  }

  const user = await User.findOne({ email: mail });
  if (!user) {
    res
      .status(404)
      .redirect(`${process.env.FRONTEND_URL}/paymentfailed`);
  }
  const endPoint = "/pg/v1/pay";

  const merchantTransactionId = uniqid();
  const userId = "1234";

  const payload = {
    merchantId: process.env.PHONE_PE_MERCHANT_ID,
    merchantTransactionId: merchantTransactionId,
    merchantUserId: userId,
    amount: parseInt(plan.price) * 100, // in paise
    redirectUrl: `https://sample-server-sand.vercel.app/redirect-url/${merchantTransactionId}/${plan.name}/${plan.days}/${user.email}/${plan.isMentor}`,
    redirectMode: "REDIRECT",
    mobileNumber: "1111111111", // to be clarified.
    paymentInstrument: {
      type: "PAY_PAGE",
    },
  };

  const bufferObj = Buffer.from(JSON.stringify(payload), "utf8");

  const base64EncodedPayload = bufferObj.toString("base64");

  const xVerify =
    sha256(base64EncodedPayload + endPoint + process.env.PHONE_PE_SALT_KEY) +
    "###" +
    process.env.PHONE_PE_SALT_INDEX;

  const options = {
    method: "post",
    url: `${process.env.PHONE_PE_HOST_URL}${endPoint}`,
    headers: {
      accept: "application/json",
      "Content-Type": "application/json",
      "X-VERIFY": xVerify,
    },
    data: {
      request: base64EncodedPayload,
    },
  };
  axios
    .request(options)
    .then(function (response) {
      res.redirect(response.data.data.instrumentResponse.redirectInfo.url);
    })
    .catch(function (error) {
      res
        .status(500)
        .redirect(`${process.env.FRONTEND_URL}/paymentfailed`);
    });
});

const SCOPES = ["https://www.googleapis.com/auth/calendar"];

const oauth2Client = new google.auth.OAuth2(
  process.env.WEBCLIENT_ID,
  process.env.WEBCLIENT_SECRET,
  process.env.REDIRECT_URL
);

async function createMeetEvent(auth, webinar) {
  const calendar = google.calendar({ version: "v3", auth });

  const event = {
    summary: webinar.title,
    start: {
      dateTime: webinar.startTime,
      timeZone: "Asia/Kolkata",
    },
    end: {
      dateTime: webinar.endTime,
      timeZone: "Asia/Kolkata",
    },
    conferenceData: {
      createRequest: {
        conferenceSolutionKey: {
          type: "hangoutsMeet",
        },
        requestId: "Surelywork_webinar",
      },
    },
    attendees: [],
  };

  try {
    const response = await calendar.events.insert({
      calendarId: "primary",
      resource: event,
      conferenceDataVersion: 1,
    });
    console.log(response.data);
    return response.data;
  } catch (error) {
    console.error("Error creating event: ", error);
    throw error;
  }
}

// app.get('/auth', (req, res) => {
//   const authUrl = oauth2Client.generateAuthUrl({
//     access_type: 'offline',
//     scope: SCOPES,
//   });
//   console.log(authUrl)
//   res.redirect(authUrl);
// });

app.get("/oauth2callback", async (req, res) => {
  const { code, state } = req.query;
  const { tokens } = await oauth2Client.getToken(code);
  oauth2Client.setCredentials(tokens);
  console.log(req.body);
  const { webinarId } = JSON.parse(state);
  res.redirect(`/create-meet-event?webinarId=${webinarId}`);
});

app.get("/create-meet-event", async (req, res) => {
  try {
    const { webinarId } = req.query;
    const webinar = await Webinar.findById(webinarId);
    if (!webinar) {
      return res.status(404).send("Webinar not found");
    }
    const event = await createMeetEvent(oauth2Client, webinar);
    console.log(event);
    res.redirect(`${process.env.FRONTEND_URL}/webinars`);
  } catch (error) {
    res.status(500).send("Error creating event");
  }
});

const IMAGE_PATH = "./webinar.jpg"

app.post("/create-webinar", async (req, res) => {
  try {
    console.log("Starting create-webinar endpoint");

    const { mail, webinar } = req.body;
    if (!webinar) return res.status(404).send("Details not found for the webinar.");

    console.log("Fetching mentor and user");
    const [mentor, user] = await Promise.all([
      Mentor.findOne({ email: mail }),
      User.findOne({ email: mail })
    ]);

    if (!mentor) return res.status(404).send("Mentor not found");
    if (!user) return res.status(404).send("User not found");
    if (!mentor.isPremium) return res.status(400).send("Subscribe to any of our plans to create a webinar.");

    console.log("Processing dates");
    const startTimeUTC = new Date(webinar.startTime);
    const endTimeUTC = new Date(webinar.endTime);
    webinar.startTime = startTimeUTC;
    webinar.endTime = endTimeUTC;

    let finalWebinar;

    try {
      console.log("Formatting date and processing image");
      const formattedDate = formatWebinarDate(startTimeUTC);
      const imageBuffer = await processWebinarImage(webinar.title, user.name, formattedDate);

      finalWebinar =  await uploadWebinarImage(imageBuffer, webinar);

    } catch (err) {
      console.error("Error processing webinar image:", err);
      return res.status(500).send("Error processing webinar image");
    }

    console.log("Creating new webinar");
    console.log(finalWebinar)
    const newWebinar = new Webinar({
      ...finalWebinar,
      liveLink: "/",
      creator: { id: mentor._id, name: user.name, photo: mentor.profilePhoto.url },
      participants: [user._id]
    });

    await newWebinar.save();
    user.myWebinars.unshift(newWebinar._id);
    await user.save();

    const authUrl = generateAuthUrl(newWebinar._id);
    console.log("Webinar created successfully");
    res.status(200).send(authUrl);
  } catch (error) {
    console.error("Error creating webinar:", error);
    return res.status(500).send(error.message);
  }
});

async function processWebinarImage(title, userName, formattedDate) {
  try {
    console.log("Reading image");
    const image = await Jimp.read(IMAGE_PATH);
    const sm = await Jimp.loadFont(Jimp.FONT_SANS_32_WHITE);
    const lg = await Jimp.loadFont(Jimp.FONT_SANS_64_WHITE);

    console.log("Printing text on image");
    image.print(sm, 30, 20, "Surely Work | Webinar")
         .print(lg, 30, 130, { text: title, alignmentX: Jimp.HORIZONTAL_ALIGN_LEFT }, 800)
         .print(sm, 30, 400, formattedDate)
         .print(sm, 400, 400, userName);

    console.log("Getting image buffer");
    return await image.getBufferAsync(Jimp.MIME_JPEG);
  } catch (error) {
    console.error("Error processing webinar image:", error);
    throw new Error("Error processing webinar image");
  }
}

async function uploadWebinarImage(imageBuffer, webinar) {
  return new Promise((resolve, reject) => {
    console.log("Uploading image to Cloudinary");
    const uploadStream = cloud.uploader.upload_stream(
      { folder: "LearnDuke", width: 150, crop: "scale" },
      (error, result) => {
        if (error) {
          console.error("Error uploading webinar photo:", error);
          reject(new Error("Error uploading webinar photo:", error));
        } else {
          console.log("Image uploaded to Cloudinary successfully");
          webinar.photo = {
            public_id: result.public_id,
            url: result.secure_url
          }; 
          resolve(webinar);
        }
      }
    );
    streamifier.createReadStream(imageBuffer).pipe(uploadStream);
  });
}

function formatWebinarDate(date) {
  return `${date.getDate()}/${date.getMonth() + 1}/${date.getFullYear()}`;
}

function generateAuthUrl(webinarId) {
  return oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: SCOPES,
    state: JSON.stringify({ webinarId }),
  });
}

//for deleting the webinar
app.delete("/delete-webinar", async (req, res) => {
  try {
    const { id, mail } = req.body;
    const user = await User.findOne({ email: mail });
    if (!user) {
      return res.status(404).send("User not found");
    }
    if (!id) {
      return res.status(404).send("Id not provided");
    }

    await Webinar.findByIdAndDelete(id);

    user.myWebinars = user.myWebinars.filter((web) => web.id !== id);

    await user.save();

    return res.status(200).send("Webinar deleted Succesfully.");
  } catch (error) {
    return res.status(500).send("Internal Server Error");
  }
});
app.get("/live-webinars", async (req, res) => {
  const { page = 1, limit = 1 } = req.query;

  try {
    const webinars = await Webinar.find({ status: "Live" })

      .limit(limit * 1) // Convert limit to a number

      .skip((page - 1) * limit) // Calculate the offset

      .exec();

    const count = await Webinar.countDocuments({ status: "Live" });

    res.status(200).json({
      webinars,

      totalPages: Math.ceil(count / limit),

      currentPage: page,
    });
  } catch (error) {
    res.status(500).send("Internal Server Error");
  }
});

app.get("/upcoming-webinars", async (req, res) => {
  const { page = 1, limit = 1 } = req.query;

  try {
    const webinars = await Webinar.find({ status: "Upcoming" })

      .limit(limit * 1) // Convert limit to a number

      .skip((page - 1) * limit) // Calculate the offset

      .exec();

    const count = await Webinar.countDocuments({ status: "Upcoming" });

    res.status(200).json({
      webinars,

      totalPages: Math.ceil(count / limit),

      currentPage: page,
    });
  } catch (error) {
    res.status(500).send("Internal Server Error");
  }
});

//get past webinars

app.get("/past-webinars", async (req, res) => {
  const { page = 1, limit = 1 } = req.query;

  try {
    const webinars = await Webinar.find({ status: "Past" })

      .limit(limit * 1) // Convert limit to a number

      .skip((page - 1) * limit) // Calculate the offset

      .exec();

    const count = await Webinar.countDocuments({ status: "Past" });

    res.status(200).json({
      webinars,

      totalPages: Math.ceil(count / limit),

      currentPage: page,
    });
  } catch (error) {
    res.status(500).send("Internal Server Error");
  }
});

// get my webinars
app.get("/get-my-webinars/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findOne({ email: id });
    if (!user) {
      return res.status(404).send("User not found");
    }
    const webinars = [];

    user.myWebinars.forEach(async (obj) => {
      const webinar = await Webinar.findById({ _id: obj.id });
      webinars.push(webinar);
    });

    return res.status(200).send(webinars);
  } catch (error) {
    return res.status(500).send("Internal server error");
  }
});

//get registered webinars
app.get("/my-registered-webinars", async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findOne({ email: id });
    if (!user) {
      return res.status(404).send("User not found");
    }
    const webinars = [];

    user.joinedWebinars.forEach(async (obj) => {
      const webinar = await Webinar.findById({ _id: obj.id });
      webinars.push(webinar);
    });

    return res.status(200).send(webinars);
  } catch (error) {
    return res.status(500).send("Internal server error");
  }
});

app.get("/getWhatsappNumber/:id", async (req, res) => {
  try {
    const mentor = await Mentor.findById(req.params.id);
    if (!mentor) {
      return res.status(404).send("Mentor not found");
    }
    res.status(200).send(mentor.whatsappNumber);
  } catch (err) {
    res.send(err);
  }
});

//register for a webinar
app.post("/register-for-webinar", async (req, res) => {
  try {
    const { webinarId, mail } = req.body;
    const user = await User.findOne({ email: mail });
    if (!user) {
      return res.status(404).send("User not found");
    }
    const webinar = await Webinar.findOne({ _id: webinarId });
    if (webinar.creator.id === user._id) {
      return res.status(302).send("You are the creator of webinar.");
    }
    if (!webinar) {
      return res.status(404).send("Webinar not found");
    }
    if (webinar.status === "Past") {
      return res.status(400).send("Webinar has ended");
    }
    if (webinar.participants.includes(user._id)) {
      return res.status(400).send("User has already joined the webinar");
    }

    webinar.participants.push(user._id);
    await webinar.save();
    return res.status(200).send("User joined the webinar successfully");
  } catch (error) {
    return res.status(500).send("Internal server error");
  }
});
app.post("/unregister-for-webinar", async (req, res) => {
  try {
    const { webinarId, mail } = req.body;
    const user = await User.findOne({ email: mail });
    if (!user) {
      return res.status(404).send("User not found");
    }
    const webinar = await Webinar.findOne({ _id: webinarId });
    if (webinar.creator.id === user._id) {
      return res.status(302).send("You are the creator of webinar.");
    }
    if (!webinar) {
      return res.status(404).send("Webinar not found");
    }
    if (webinar.status === "Past") {
      return res.status(400).send("Webinar has ended");
    }
    if (!webinar.participants.includes(user._id)) {
      return res
        .status(400)
        .send("User has already unregistered for the webinar");
    }
    await Webinar.updateOne(
      { _id: webinarId },
      { $pull: { participants: user._id } }
    );

    await webinar.save();
    return res
      .status(200)
      .send("User unregistered from the webinar successfully");
  } catch (error) {
    return res.status(500).send("Internal server error");
  }
});

// is eligible to join webinar
app.post("/isEligible", async (req, res) => {
  try {
    const { mail, webinarId } = req.body;
    const user = await User.findOne({ email: mail });
    if (!user) {
      return res.status(404).send("User not found");
    }
    const webinar = await Webinar.findById({ _id: webinarId });
    if (!webinar) {
      return res.status(404).send("Webinar not found");
    }
    const isRegistered = await webinar.participants.includes(
      user._id.toString()
    );
    const isCreator = webinar.creator.id.toString() === user._id.toString();

    if (isRegistered || isCreator) {
      return res.status(200).send(true);
    }
    return res.status(201).send(false);
  } catch (error) {
    return res.status(500).send("Internal server error");
  }
});

// updating the status of the webinar
const updateWebinarStatus = async () => {
  try {
    const webinars = await Webinar.find();
    webinars.forEach(async (webinar) => {
      if (webinar.status == "Past") {
        return;
      }
      let now = new Date().getTime() / 1000;
      let start = new Date(webinar.startTime).getTime() / 1000;
      let end = new Date(webinar.endTime).getTime() / 1000;

      if (webinar.status == "Upcoming" && start <= now) {
        webinar.status = "Live";
        await webinar.save();
        return;
      }
      if (webinar.status == "Live" && now > end) {
        console.log(now > end);
        webinar.status = "Past";
        await webinar.save();
        return;
      }
    });
  } catch (err) {
    console.log(err);
  }
};

// cron.schedule("* * * * *", () => {
//   console.log("Checking for webinars to update their status...");
//   updateWebinarStatus();
// });

app.get("/getWebinar/:id", async (req, res) => {
  try {
    const webinar = await Webinar.findOne({ _id: req.params.id });
    if (!webinar) {
      return res.status(404).send("Webinar not found");
    }

    console.log(`Webinar Creator ID: ${webinar.creator.id.toString()}`);

    // Assuming Mentor model uses ObjectId type for id
    const mentor = await Mentor.findOne({ _id: webinar.creator.id });
    if (!mentor) {
      return res.status(404).send("Mentor not found");
    }

    res.send({ webinar, mentor });
  } catch (error) {
    console.error("Error: ", error);
    res.status(500).send(error);
  }
});

app.get("/pay/webinar", async (req, res) => {
  try {
    const { webinarId, mail } = req.query;

    const webinar = await Webinar.findById(webinarId);
    if (!webinar) {
      return res.status(404).send("Webinar not found");
    }

    const user = await User.findOne({ email: mail });
    const mentor = await Mentor.findOne({ email: mail });
    if (!user) {
      return res.status(404).send("User not found");
    }

    if (mentor && webinar.creator.id == mentor._id) {
      return res.status(201).send("You are the creator of this webinar");
    }

    if (webinar.status === "Past") {
      return res.status(201).send("Webinar already ended");
    }
    if (webinar.isPaid == false || (webinar.price && webinar.price <= 0)) {
      return res.status(200).send("This webinar is free");
    }

    const endPoint = "/pg/v1/pay";
    const merchantTransactionId = uniqid();
    const userId = "1234";

    const payload = {
      merchantId: process.env.PHONE_PE_MERCHANT_ID,
      merchantTransactionId: merchantTransactionId,
      merchantUserId: userId,
      amount: parseInt(webinar.price) * 100, // in paise
      redirectUrl: `https://sample-server-sand.vercel.app/redirect-url/${merchantTransactionId}/${webinar._id}/${user._id}`,
      redirectMode: "REDIRECT",
      mobileNumber: "1111111111", // to be clarified.
      paymentInstrument: {
        type: "PAY_PAGE",
      },
    };

    const bufferObj = Buffer.from(JSON.stringify(payload), "utf8");
    const base64EncodedPayload = bufferObj.toString("base64");

    const xVerify =
      sha256(base64EncodedPayload + endPoint + process.env.PHONE_PE_SALT_KEY) +
      "###" +
      process.env.PHONE_PE_SALT_INDEX;

    const options = {
      method: "post",
      url: `${process.env.PHONE_PE_HOST_URL}${endPoint}`,
      headers: {
        accept: "application/json",
        "Content-Type": "application/json",
        "X-VERIFY": xVerify,
      },
      data: {
        request: base64EncodedPayload,
      },
    };

    const response = await axios.request(options);
    res.redirect(response.data.data.instrumentResponse.redirectInfo.url);
  } catch (error) {
    console.log(error);
    res
      .status(500)
      .redirect(`${process.env.FRONTEND_URL}/paymentfailed`);
  }
});


app.get(
  "/redirect-url/:merchantTransactionId/:webinarId/:userId",
  async (req, res) => {
    try {
      const { merchantTransactionId, webinarId, userId } = req.params;

      const user = await User.findById(userId);
      const webinar = await Webinar.findById(webinarId);

      if (merchantTransactionId) {
        const xVerify =
          sha256(
            `/pg/v1/status/${process.env.PHONE_PE_MERCHANT_ID}/${merchantTransactionId}${process.env.PHONE_PE_SALT_KEY}`
          ) +
          "###" +
          process.env.PHONE_PE_SALT_INDEX;

        const options = {
          method: "get",
          url: `${process.env.PHONE_PE_HOST_URL}/pg/v1/status/${process.env.PHONE_PE_MERCHANT_ID}/${merchantTransactionId}`,
          headers: {
            accept: "application/json",
            "Content-Type": "application/json",
            "X-MERCHANT-ID": merchantTransactionId,
            "X-VERIFY": xVerify,
          },
        };

        const response = await axios.request(options);
        const paymentDate = new Date();

        const paymentDetails = {
          paymentDate: paymentDate,
          plan: `Webinar - ${webinar.title}`,
          amount: parseInt(response.data?.data.amount) / 100,
          status: response.data?.code,
          user: user.email,
          transactionId: response.data?.data.transactionId,
          merchantTransactionId: merchantTransactionId,
          expirationDate: paymentDate,
          paymentMethod: response.data?.data?.paymentInstrument.type,
          pgTransactionId:
            response.data?.data?.paymentInstrument.pgTransactionId,
          arn: response.data?.data.paymentInstrument.arn,
        };

        const payment = new Payment(paymentDetails);
        await payment.save();

        if (response.data.code === "PAYMENT_SUCCESS") {
          webinar.participants.unshift(user._id);
          await user.save();
          await webinar.save();
          res.redirect(`${process.env.FRONTEND_URL}/detailedWebinar/${webinarId}`);
        } else if (response.data.code === "PAYMENT_ERROR") {
          return res.redirect(
            `${process.env.FRONTEND_URL}/paymentfailed`
          );
        }
      } else {
        return res.redirect(
          `${process.env.FRONTEND_URL}/paymentfailed`
        );
      }
    } catch (error) {
      console.log(error);
      if (!res.headersSent) {
        return res.redirect(
          `${process.env.FRONTEND_URL}/paymentfailed`
        );
      }
    }
  }
);
/* -------------------------------------------------------------------------- */

app.get("/", (req, res) => {
  res.send("Home Page");
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
