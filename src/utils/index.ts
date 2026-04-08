import jwt from 'jsonwebtoken';
import { ACCESS_JWT_SECRET, ACCESS_TOKEN_TTL } from '#config';
import { randomUUID } from 'node:crypto';
import { RefreshToken } from '#models';

export const signAccessToken = (userId: string, roles: string[]) => {
  return jwt.sign({ roles }, ACCESS_JWT_SECRET, { expiresIn: ACCESS_TOKEN_TTL, subject: userId });
};

export const createAndPersistRefreshToken = async (userId: string) => {
  const token = randomUUID();
  await RefreshToken.create({
    token,
    userId
  });
  return token;
};
