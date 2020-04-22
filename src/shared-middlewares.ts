import * as bodyParser from 'body-parser'
import { ErrorRequestHandler, RequestHandler } from 'express'
import * as csrf from 'csurf';
import * as cors from 'cors';
/**
 * Use same body-parser options as json-server
 */
export const bodyParsingHandler = [
	bodyParser.json({ limit: '10mb' }),
	bodyParser.urlencoded({ extended: false }),
]

/**
 * Json error handler
 */
export const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
	console.error(err)
	res.status(500).jsonp(err.message)
}

/**
 * Just executes the next middleware,
 * to pass directly the request to the json-server router
 */
export const goNext: RequestHandler = (req, res, next) => {
	next()
}

/**
 * Look for a property in the request body and reject the request if found
 */
export function forbidUpdateOn(...forbiddenBodyParams: string[]): RequestHandler {
	return (req, res, next) => {
		const bodyParams = Object.keys(req.body)
		const hasForbiddenParam = bodyParams.some(forbiddenBodyParams.includes)

		if (hasForbiddenParam) {
			res.status(403).jsonp(`Forbidden update on: ${forbiddenBodyParams.join(', ')}`)
		} else {
			next()
		}
	}
}

type RequestMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'HEAD'

/**
 * Reject the request for a given method
 */
export function forbidMethod(method: RequestMethod): RequestHandler {
	return (req, res, next) => {
		if (req.method === method) {
			res.sendStatus(405)
		} else {
			next()
		}
	}
}

/**
 * 
 */
export const csrfTokenErrorHandler = (err, req, res, next) => {
	if (err.code !== 'EBADCSRFTOKEN') return next(err)

	// handle CSRF token errors here
	res.status(403).jsonp('cannot process form')
};

export function extractCookieToken(cookie, token = 'token') {
	const initialIndex = cookie.indexOf(`${token}=`);
	let ret = cookie.substr(initialIndex + `${token}=`.length);
	return ret.substr(0, ret.indexOf(';'));
}
export const validateCors = (whiteList = ['http://localhost:4200', 'http://localhost:3000']) => cors({
	origin: (url, callback) => {
		if (whiteList.includes(url)) {
			callback(null, true);
		} else {
			callback(new Error('Not allowed by CORS'));
		}
	}
})
export const attachCsrfToken = (tokenName = 'XSRF-TOKEN') => (req: any, res, next) => {
	// Pass the Csrf Token
	res.cookie(tokenName, req.csrfToken(), {
		httpOnly: false,
		path: '/'
	});
	next()
};
export const validateCsrfToken = csrf({ cookie: true });