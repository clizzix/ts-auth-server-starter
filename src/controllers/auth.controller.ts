import type { RequestHandler } from 'express';
import { REFRESH_TOKEN_TTL, SALT_ROUNDS } from '#config';
import { RefreshToken, User } from '#models';
import type { registerSchema, loginSchema } from '#schemas';
import { z } from 'zod';
import bcrypt from 'bcrypt';
import { signAccessToken, createAndPersistRefreshToken } from '#utils';

type RegisterinputDTO = z.infer<typeof registerSchema>;
type LoginInputDTO = z.infer<typeof loginSchema>;

const isProduction = process.env.NODE_ENV === 'production';
const cookieOptions = {
  httpOnly: true,
  sameSite: isProduction ? ('none' as const) : ('lax' as const),
  secure: isProduction,
  maxAge: REFRESH_TOKEN_TTL * 1000
};

export const register: RequestHandler<unknown, unknown, RegisterinputDTO> = async (req, res) => {
  const { firstName, lastName, email, password } = req.body;
  if (!firstName || !lastName || !email || !password) {
    res.status(400).json({
      error: 'first name, last name, email, password are required'
    });
    return;
  }
  const found = await User.findOne({ email });
  if (found) {
    res.status(400).json({ error: 'User already exists' });
    return;
  }
  const salt = await bcrypt.genSalt(SALT_ROUNDS);
  const hashedPW = await bcrypt.hash(password, salt);
  const user = await User.create({ ...req.body, password: hashedPW } satisfies RegisterinputDTO);
  const accessToken = signAccessToken(user._id.toString(), user.roles);
  const refreshToken = await createAndPersistRefreshToken(user._id.toString());
  res.cookie('refreshToken', refreshToken, cookieOptions);
  res.status(201).json({ message: 'User registered successfully', accessToken });
};

export const login: RequestHandler<unknown, unknown, LoginInputDTO> = async (req, res) => {
  // TODO: Implement user login
  // Query the DB for an existing user with that email (make sure to .select('+password') so we can compare it to the hashed password)
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({ error: 'Email and password are required' });
    return;
  }
  const user = await User.findOne({ email }).select('+password');
  // Throw an error is a user with that email is NOT found
  if (!user) {
    res.status(400).json({ error: 'User with that email is not found' });
    return;
  }
  // Compare the hashed password to the password the user provided
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    res.status(400).json({ error: 'Wrong password!' });
    return;
  }
  // Delete all refresh tokens from that user
  await RefreshToken.deleteMany({ userId: user._id });
  // Generate access token (JWT) and refresh token (random string saved to database)
  const accessToken = signAccessToken(user._id.toString(), user.roles);
  const refreshToken = createAndPersistRefreshToken(user._id.toString());
  // Send the access token (in the response body) and the refresh token (in a cookie)
  res.cookie('refreshToken', refreshToken, cookieOptions);
  res.json({ message: 'Logged in successfully', accessToken });
};

export const refresh: RequestHandler = async (req, res) => {
  // TODO: Implement access token refresh and refresh token rotation
  // Destructure the refreshToken from req.cookies
  const { refreshToken } = req.cookies;
  if (!refreshToken) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  // Throw an error if there is no refreshToken cookie
  const storedToken = await RefreshToken.findOne({ token: refreshToken });
  // Query the database for the matching stored refresh token
  // Throw an error if no stored token was found
  if (!storedToken) {
    res.clearCookie('refresh Token', cookieOptions);
    res.status(401).json({ error: 'Invalid or expired refresh token' });
    return;
  }
  // Delete the stored token (since we'll be rotating it with a new refresh token)
  await RefreshToken.deleteOne({ _id: storedToken._id });
  // Query the database for the user associated with that token
  const user = await User.findById(storedToken.userId);
  // Throw an error if no user is found
  if (!user) {
    res.status(401).json({ error: 'User no longer exists' });
    return;
  }
  // Generate access token (JWT) and refresh token (random string saved to database)
  const accessToken = signAccessToken(user._id.toString(), user.roles);
  const newRefreshToken = await createAndPersistRefreshToken(user._id.toString());
  // Send the access token (in the response body) and the refresh token (in a cookie)
  res.cookie('refreshToken', newRefreshToken, cookieOptions);
  res.json({ accessToken });
};

export const logout: RequestHandler = async (req, res) => {
  // TODO: Implement logout by removing the tokens
  //   Get the refreshToken cookie
  // If a refreshToken cookie is found, delete the corresponding stored token from the database
  // Clear the refreshToken cookie
  // Send a success message in the response body
  res.json({ message: 'DELETE /refresh' });
};

export const me: RequestHandler = async (req, res, next) => {
  // TODO: Implement a me handler
  // Get the access token from the request headers
  // Get the Authorization header from the request
  // Isolate the access token
  // Throw an error if there is not access token
  // Verify the access token
  // If token is expired, add code: ACCESS_TOKEN_EXPIRED to error
  // Query the database for the user who is the sub of the access token
  // Throw an error if no user is found
  // Send user profile with success message in response body
  res.json({ message: 'GET /me' });
};
