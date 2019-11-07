const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = (req, res, next) => {
    // GET token from header
    const token = req.header('x-auth-token');

    //check if not token
    if (!token) {
        return res.status(401).json({ msg: 'No token, Authorization denied' });
    }

    //Verify token
    try {

        const decode = jwt.verify(token, config.get('jwtSecretToken'));

        req.user = decode.user;
        next();

    } catch (err) {

        res.status(401).json({ msg: 'Token is not valid' });

    }
}
