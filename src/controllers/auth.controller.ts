import type { RequestHandler } from 'express';
import { ACCESS_JWT_SECRET, REFRESH_TOKEN_TTL, SALT_ROUNDS } from '#config';
import { RefreshToken, User } from '#models';
import type { registerSchema, loginSchema } from '#schemas';
import { z } from 'zod';
import bcrypt from 'bcrypt';
import { signAccessToken, createAndPersistRefreshToken } from '#utils';
import jwt from 'jsonwebtoken';

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
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({ error: 'Email and password are required' });
    return;
  }
  const user = await User.findOne({ email }).select('+password');
  if (!user) {
    res.status(400).json({ error: 'User with that email is not found' });
    return;
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    res.status(400).json({ error: 'Wrong password!' });
    return;
  }
  await RefreshToken.deleteMany({ userId: user._id });

  const accessToken = signAccessToken(user._id.toString(), user.roles);
  const refreshToken = await createAndPersistRefreshToken(user._id.toString());
  res.cookie('refreshToken', refreshToken, cookieOptions);
  res.json({ message: 'Logged in successfully', accessToken });
};

export const refresh: RequestHandler = async (req, res) => {
  const { refreshToken } = req.cookies;
  if (!refreshToken) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  const storedToken = await RefreshToken.findOne({ token: refreshToken });
  if (!storedToken) {
    res.clearCookie('refresh Token', cookieOptions);
    res.status(401).json({ error: 'Invalid or expired refresh token' });
    return;
  }

  await RefreshToken.deleteOne({ _id: storedToken._id });

  const user = await User.findById(storedToken.userId);
  if (!user) {
    res.status(401).json({ error: 'User no longer exists' });
    return;
  }

  const accessToken = signAccessToken(user._id.toString(), user.roles);
  const newRefreshToken = await createAndPersistRefreshToken(user._id.toString());

  res.cookie('refreshToken', newRefreshToken, cookieOptions);
  res.json({ accessToken });
};

export const logout: RequestHandler = async (req, res) => {
  const { refreshToken } = req.cookies;
  if (refreshToken) await RefreshToken.deleteOne({ token: refreshToken });

  res.clearCookie('refreshToken');
  res.json({ message: 'Refresh token has been removed successfully' });
};

export const me: RequestHandler = async (req, res, next) => {
  try {
    const authHeader = req.header('authorization');
    const accessToken = authHeader?.startsWith('Bearer') && authHeader.split(' ')[1];
    if (!accessToken) throw new Error('Access token is required', { cause: { status: 401 } });

    const decoded = jwt.verify(accessToken, ACCESS_JWT_SECRET) as jwt.JwtPayload;

    const user = await User.findById(decoded.sub).select('-password').lean();
    if (!user) throw new Error('User not found', { cause: { status: 401 } });

    res.json({ message: 'User profile', user });
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      next(
        new Error('Expired access token', {
          cause: { status: 401, code: 'ACCESST_TOKEN_EXPIRED' }
        })
      );
    } else {
      next(new Error('Invalid access token', { cause: { status: 401 } }));
    }
    next(error);
  }
};
