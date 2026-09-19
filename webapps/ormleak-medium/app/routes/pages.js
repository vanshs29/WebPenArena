const express = require('express')
const { requireAuth } = require('../auth')

const router = express.Router()

router.get('/', (req, res) => res.render('index'))

router.get('/dashboard', requireAuth, (req, res) => res.render('dashboard', { user: req.user }))

router.get('/profile', requireAuth, (req, res) => res.render('profile', { user: req.user }))

module.exports = { router }
