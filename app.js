const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer')
const mongoose = require('mongoose');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const errorController = require('./controllers/error');
const User = require('./models/user');
const adminRoutes = require('./routes/admin');
const shopRoutes = require('./routes/shop');
const authRoutes = require('./routes/auth');
const csrf = require('csurf');
const flash = require('connect-flash');
/*############################################################*/
// Constants
const MONGODB_URI =
    'mongodb+srv://ahmedOkila:h42u1t48JINEYFjP@cluster0.8i4b5.mongodb.net/shop';
const app = express();
const store = new MongoDBStore({
    uri: MONGODB_URI,
    collection: 'sessions'
});
const csrfProtection = csrf();
const fileStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, './images')
    },
    filename: function (req, file, cb) {
        cb(null, new Date().toISOString().replace(/:/g, '-') + '-' + file.originalname);
    }
})
const fileFilter = (req, file, cb) => {
    if (
        file.mimetype === 'image/png' ||
        file.mimetype === 'image/jpg' ||
        file.mimetype === 'image/jpeg'
    ) {
        cb(null, true);
    } else {
        cb(null, false);
    }
}
app.set('view engine', 'ejs');
app.set('views', 'views');
/*############################################################*/
//Middlewares
/*
 !This Middleware to parse the Incoming Requests with enctype=application/x-www-form-urlencoded
 !Which means it only sees text Data
 */
app.use(bodyParser.urlencoded({extended: false}));
app.use(
    multer({storage: fileStorage, fileFilter: fileFilter}).single('image')
);
/*
 ?  First Middleware
 ! This Middleware means any Route implicitly ends with .css, .js
 ! It will be forwarded inside public directory and NodeJS is Smart enough
 ! to detect that the path will be considered after / keyword
 ?  Second Middleware which is commented is the same as First Middleware
 ! This Middleware means any Route begins with /public
 ! It will be forwarded inside public directory and NodeJS is Smart enough
 ! to detect that the path will be considered after public keyword
 */
app.use(express.static(path.join(__dirname, 'public')));
// app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/images', express.static(path.join(__dirname, 'images')));
//! This Middleware of Session Initialization
app.use(
    session({
        secret: 'my secret',
        resave: false,
        saveUninitialized: false,
        store: store
    })
);
//! This Middleware of Flash must be Initialized Just after Session Initialization
app.use(flash());
/*
 ! This Middleware to ensure that the user is Opening a Session
 ! with our server or not for each new Request?

 ? iF the user is on Active Session then we would like to set a user Property to each
 ? new Request with the user Model to be able to execute all its Functionalities

 ? If the user is not on a Session then he will be continued until login Route
 ? at which we will set to its session a property user (plain text not user Model) and then
 ? will be redirected to any other path until he gets to this middleware again where he will be
 ? on active session.
 */
app.use((req,
         res,
         next) => {
    if (!req.session.user) {
        return next();
    }
    User.findById(req.session.user._id)
        .then(user => {
            req.user = user;
            next();
        })
        .catch(err => console.log(err));
});
/*
! First Middleware
? For Every Request passing this Middleware; it should have the csrf token to pass to next Middleware
! Second Middleware
? For Every Request passing this Middleware; we will set these 2 variables as
? Input Properties for each view rendered.
*/
app.use(csrfProtection);
app.use((req,
         res,
         next) => {
    res.locals.isAuthenticated = req.session.isLoggedIn;
    res.locals.csrfToken = req.csrfToken();
    next();
});
app.use('/admin', adminRoutes);
app.use(shopRoutes);
app.use(authRoutes);
app.get('/500', errorController.get500);
app.use(errorController.get404);
//! Error Handling Middleware
// app.use((error,
//          req,
//          res,
//          next) => {
//     res.status(500).render('500', {
//         pageTitle: 'Error!',
//         path: '/500',
//         isAuthenticated: req.session.isLoggedIn
//     });
// })
/*############################################################*/
mongoose
    .connect(MONGODB_URI, {useNewUrlParser: true, useUnifiedTopology: true})
    .then(result => {
        app.listen(3000);
    })
    .catch(err => {
        console.log(err);
    });
/*############################################################*/
