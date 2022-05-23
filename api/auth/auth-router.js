const bcrypt = require('bcryptjs')
const express = require('express')
const Users = require('../users/users-model')

const router = express.Router()
const {checkPasswordLength, checkUsernameExists, checkUsernameFree} = require('./auth-middleware')
// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!


/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/register', checkPasswordLength, checkUsernameFree, async (req, res) => {
  const {username, password} = req.body
  let hash = bcrypt.hashSync(password, 8)
  let result = await Users.add({username, password: hash})
  res.status(200).json(result)
})


/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

  router.post('/login', checkUsernameExists, (req, res, next) => {
    const {password} = req.body

    // let user = await Users.findBy({username}).first()
    if(bcrypt.compareSync(password, req.user.password)){
      req.session.user = req.user;
      res.status(200).json({message: `Welcome ${req.user.username}`})
    } else {
       next({status: 401, message: 'Invalid credentials'})
    }
})



/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get('/logout', (req, res, next) => {
  if(req.session.user != null) {
    req.session.destroy()
    res.status(200).json({message: 'you are now logged out'})
  } else {
    res.status(400).json({message:'you are already logged out'})
  }
})
 
router.get('/getThing', (req,res) => {
  res.json({thing: req.session.thing ?? null})
})

// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;