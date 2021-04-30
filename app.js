//jshint esversion:6
require('dotenv').config();
const express = require('express');
const app = express();

const ejs = require('ejs');
const bodyParser = require('body-parser');

const mongoose = require('mongoose');
const passport = require('passport');
//const passport-local = require('passport-local');
const passportLocalMongoose = require('passport-local-mongoose');
const session = require('express-session');
var GoogleStrategy = require('passport-google-oauth20').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var findOrCreate = require('mongoose-findorcreate')
const HttpsProxyAgent = require('https-proxy-agent');
require('https').globalAgent.options.rejectUnauthorized = false;
//const md5 = require('md5');
//const bcrypt = require('bcrypt');
//const saltRounds = 10;
app.use(session({
  secret: 'out little secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    expires: false,
  }
}));
app.use(passport.initialize());
app.use(passport.session());
mongoose.connect("mongodb+srv://admin-uzma:" + process.env.PWD + "@cluster0.oqnhu.mongodb.net/secretsUserDb", {useNewUrlParser: true, useUnifiedTopology: true})

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
mongoose.set('useCreateIndex', true);

const userSchema =new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
  facebookId: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser(function(user, done) {
//   done(null, user.id);
// })); //necessary when using sessions
// passport.deserializeUser(User.deserializeUser(function(id, done) {
//   User.findById(id, function(err, user) {
//    done(err, user);
//  });
// }));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  })
});


const gStrategy = new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    // Make Strategy trust all proxy settings
    proxy: true
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
);
const agent = new HttpsProxyAgent(process.env.HTTP_PROXY || "http://192.168.23.4:999/");
gStrategy._oauth2.setAgent(agent);

passport.use(gStrategy);

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log("Facebook profile" + profile)
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render("home");
});

//initiate authentication with google. use passport
//this brings popup to login to google account
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));


//below route should be similar to the one given in the gooogle dev docs
app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

// app.post("/register", function(req, res){
//   bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//     // Store hash in your password DB.
//     const newUser = new User({
//       email: req.body.username,
//       password: hash
//     });
//     newUser.save(function(err){
//       if(err)
//         console.log(err);
//       else
//         res.render('secrets');
//     });
//   });
// });

app.get("/secrets", function(req, res){
  console.log(req.isAuthenticated());//false if not authenticated
  console.log(req.user);// undefined if no user
  User.find({"secret": {$ne:null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    }else{
      if(foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers, authenticated: req.isAuthenticated()});
      }
    }
  })
});

app.post("/register", function(req, res){
  const username = req.body.username;
  const password = req.body.password;
  User.register({username:username}, password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect('register');
    }else{
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      })
    }
      // Value 'result' is set to false. The user could not be authenticated since the user is not active
    });
  });

app.post("/login", function(req, res){
  const user = new User({
    userName: req.body.username,
    password: req.body.password
  });
  req.login(user, function(err) {
    if (err) { console.log(err); }
    else{
      passport.authenticate("local")(req, res, function(){
        res.redirect('secrets');
      });
    }
  });
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("login");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;
  const user = req.user.id;
  User.findById(user, function(err, foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function(req, res){
  //deauthenticate user and end session
  req.logout();
  res.redirect("/");
})
// app.post("/login", function(req, res){
//   const userName = req.body.username;
//   const password = req.body.password;
//   User.findOne({email: userName}, function(err, foundUser){
//     if(err)
//       console.log(err);
//     else {
//       if(foundUser){
//         bcrypt.compare(password, foundUser.password, function(err, result){
//           if(result)
//             res.render("secrets");
//           else
//             res.send("You don't have an account");
//         });
//         // if(foundUser.password === password){
//         //   res.render("secrets");
//         // }else{
//         //   res.send("You don't have an account");
//         // }
//       }
//     }
//   })
// });

app.listen(process.env.PORT || 3000, function(){
  console.log("listening...")
})
