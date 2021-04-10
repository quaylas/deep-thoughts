const jwt = require('jsonwebtoken');
require('dotenv').config('../.env');

const expiration = '2h';

const signToken = function({ username, email, _id }) {
    const payload = { username, email, _id };
    const secret = process.env.JWT_SECRET;
    
    return jwt.sign({ data: payload }, secret, { expiresIn: expiration });
};

const authMiddleware = function({ req }) {
    let token = req.body.token || req.query.token || req.headers.authorization;
    const secret = process.env.JWT_SECRET;

    // separate "Bearer" from token value
    if(req.headers.authorization){
        token = token
        .split(' ')
        .pop()
        .trim();
    }

    // if no token, return request object as-is
    if(!token) {
        return req;
    }

    try {
        // decode and attach user data to request object
        const { data } = jwt.verify(token, secret, { maxAge: expiration });
        req.user = data;
    } catch {
        console.log('Invalid token');
    }

    // return updated request object
    return req;
};

module.exports = {
    signToken ,
    authMiddleware
};