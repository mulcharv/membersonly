const createError = require('http-errors');
const express = require('express');
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require("bcryptjs");
mongoose.set("strictQuery", false);
require('dotenv').config()
const dev_db_url = process.env.MONGOURL;
const mongoDB = dev_db_url;
const asyncHandler = require("express-async-handler");
const { body, validationResult, customSanitizer } = require("express-validator"); 
const multer = require('multer');
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
const compression = require('compression');
const helmet = require('helmet');
const RateLimit = require("express-rate-limit");
const port = process.env.PORT || 3000;



const User = require("./models/user");
const Message = require("./models/message");

const limiter = RateLimit({ 
  windowMs: 1 * 60 * 1000,
  max: 20,
})


mongoose.set("strictQuery", false);
main().catch((err) => console.log(err));
async function main() {
  await mongoose.connect(mongoDB);
}



const app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(session({
  secret: 'blueberries',
  resave: false,
  saveUninitialized: true
}));

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(compression());
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      'script-src': ["'self'", "code.jquery.com", "cdn.jsdelivr.net"],
      "img-src": ["'self'", "https: data:"]
    },
  })
);
app.use(limiter);


passport.use(
  new LocalStrategy(
    async(username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      } else {
        bcrypt.compare(password, user.password, (err, res) => {
          if (res === true) {
              return done(null, user)
          } else {
              return done(null, false, {message: "Incorrect password"})
          }
      }); }
  } catch(err) {
      return done(err);
  };
})
);

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function(id, done) {
  try {
      const user = await User.findById(id);
      done(null, user);
  } catch(err) {
      done(err);
  };
});

app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));
app.use(function(req, res, next) {
  res.locals.currentUser = req.user;
  next();
});



app.get("/", asyncHandler(async(req, res, next) => {
  const messages = await 
    Message.find().sort({ createdAt: -1 }).populate('author').exec();
  
  if (req.user === undefined ) {
    res.render("index", { 
      storeduser: false,
      messages: messages,
     })
  } 
  else {
  res.render("index", { 
    storeduser: req.user,
    messages: messages,
   }); 
  }
}));

app.post('/delete', asyncHandler(async(req, res, next) => {
  await Message.findByIdAndRemove(req.body.messageid);
        res.redirect('/');
}))

app.get("/signup", asyncHandler(async(req, res, next) => {
  if (req.user === undefined) {
  res.render("signup_form", {
    storeduser: false
  })
  }
  else {
    res.render("signup_form", {
      storeduser: req.user
    })
  }

}))

app.post("/signup", upload.single('profile_image'), [
  body('firstname', 'First name must not be empty.')
    .trim()
    .isLength({ min: 1 })
    .escape(),
  body('lastname', 'Last name must not be empty.')
    .trim()
    .isLength({ min: 1 })
    .escape(),
  body('username')
    .trim()
    .isLength({ min: 1 })
    .escape()
    .custom(async value => {
      const existingUser = await User.findOne({ username: value});
      if (existingUser) {
        throw new Error('Username already in use');
      }
    })
    .withMessage('Username must not be empty'),
  body('password')
    .trim()
    .isLength({ min: 1 }),
  body('passwordConfirmation').custom((value, { req }) => {
    return value === req.body.password;
  }),
  body('profile_image').custom((value, {req}) => {
    if (!req.file) throw new Error('Profile image is required');
    return true;
  }),
  body('adminstatus')
  .optional({ values: "falsy"})
  .customSanitizer(input => {
    return Boolean(input)
  }),
  asyncHandler(async(req, res, next) => {

    const errors = validationResult(req);

    const user = new User({
      first_name: req.body.firstname,
      last_name: req.body.lastname,
      username: req.body.username,
      password: req.body.password,
      profile_image: req.file.buffer,
      membership_status: false,
      admin_status: req.body.adminstatus,
    });

    if (!errors.isEmpty()) {
      res.render("signup_form", {
        user: user,
        errors: errors.array(),
      });
      return;
    } else {
      let salt = bcrypt.genSaltSync(10);
      let hash = bcrypt.hashSync(req.body.password, salt);
      user.password= hash;
      await user.save();

      res.redirect('/')
    }

})
]
)

app.get("/login", asyncHandler(async(req, res, next) => {
  if (req.user === undefined) {
    res.render("login_form", {
      storeduser: false
    })
    }
    else {
      res.render("login_form", {
        storeduser: req.user
      })
    }
}))

app.post("/login",
  passport.authenticate("local", { failureRedirect: '/login', failureMessage: true }),
  function(req, res, next) {
    console.log('success')
    res.redirect('/');
  }
);

app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
      if (err) {
          return next(err);
      }
      res.redirect("/");
  });
});

app.get("/membership", asyncHandler(async(req, res, next) => {
  if (req.user === undefined) {
    res.render("membership_form", {
      storeduser: false
    })
    }
    else {
      res.render("membership_form", {
        storeduser: req.user
      })
    }
}))

app.post("/membership", asyncHandler(async(req, res, next) => {
  if (req.body.membershipcode.toLowerCase() === process.env.MEMBERSHIP_KEY) {
    const user = await User.findByIdAndUpdate(req.user._id, { membership_status: true }).exec();

    res.redirect('/')
  } else {
    res.render('membership_form', { errmessage: 'Incorrect Answer'})
  }
}))

app.get("/message", asyncHandler(async(req, res, next) => {
  if (req.user === undefined) {
    res.render("message_form", {
      storeduser: false
    })
    }
    else {
      res.render("message_form", {
        storeduser: req.user
      })
    }
}))

app.post("/message", [
  body('messagetext')
  .trim()
  .isLength({ min: 1 })
  .escape(),
  asyncHandler(async(req, res, next) => { 
    const errors = validationResult(req);

    const message = new Message({
      message_text: req.body.messagetext,
      author: req.user._id,
    });

    if (!errors.isEmpty()) {
      res.render("message_form", {
        errors: errors.array(),
      });
      return;
    } else {
      await message.save();

      res.redirect('/');
    }

  })

])

module.exports = app;
