/*
if there is an error thrown in an asynchronous function passed
asyncMiddleware, then asyncMiddleware
will pass the error to next() and express will handle the error
by sending the client a 500 code with an explanation of the error;
*/

export const asyncMiddleware = fn =>
  (req, res, next) => {
    Promise.resolve(fn(req, res, next))
      .catch(next);
};
