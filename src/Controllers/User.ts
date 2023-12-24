import {
  Controller,
  Get,
  Middleware,
  Patch,
  Post,
  Put
} from '@overnightjs/core';
import { Request, Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { DataSource, Repository } from 'typeorm';
import { sign, verify } from 'jsonwebtoken';
import { hash, compare } from 'bcrypt';
import multer from 'multer';
import path from 'path';
import { logger } from '../';

import { UserData } from '../Models';
import { config } from '../config';

const JWT_SECRET = config.secret;

const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,25}$/; // At least one letter, one number, 8-25 characters
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/; // Basic email regex
const usernameRegex = /^[A-Za-z\d]{1,12}$/; // Alphanumeric, 1-12 characters

const validatePassword = (password: string) => passwordRegex.test(password);
const validateEmail = (email: string) => emailRegex.test(email);
const validateUsername = (username: string) => usernameRegex.test(username);

const generateToken = (user: UserData) => {
  const expiresIn = '1h'; // or any suitable duration
  const payload = { username: user.username, id: user.id };
  return sign(payload, JWT_SECRET, { expiresIn });
};

const verifyToken = (token: string): UserData | null => {
  try {
    return verify(token, JWT_SECRET) as UserData;
  } catch (error) {
    // Handle token verification error
    return null;
  }
};

const fileFilter = (req: any, file: any, cb: any) => {
  // Allowed file extensions
  const filetypes = /jpeg|jpg|png/;
  // Check extension
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  // Check mimetype
  const mimetype = filetypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb('Error: Images Only!');
  }
};

const authenticateToken = async (
  req: Request | any,
  res: Response,
  next: NextFunction
) => {
  if (!req.cookies) {
    return res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ error: 'Access denied, no cookies' });
  }
  const token = req.cookies.jwt;

  if (!token) {
    return res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ error: 'Access denied, no token cookie' });
  }

  try {
    const verified = verifyToken(token);
    if (!verified) {
      return res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ error: 'Invalid token' });
    }

    req.user = verified;
    next();
  } catch (error) {
    res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ error: 'An error occurred' });
  }
};

const storage = multer.diskStorage({
  destination: (req: Request, file: any, cb: any) => {
    cb(null, 'uploads/');
  },
  filename: (req: Request, file: any, cb: any) => {
    cb(
      null,
      file.fieldname + '-' + Date.now() + path.extname(file.originalname)
    );
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 1000000 },
  fileFilter
}).single('profilePic');

@Controller('user')
export class UserController {
  private userDataRepository: Repository<UserData>;

  constructor(dataSource: DataSource) {
    this.userDataRepository = dataSource.getRepository(UserData);
  }

  @Get('info/:username')
  private async getUserInfo(req: Request, res: Response) {
    try {
      const user = await this.userDataRepository.findOneBy({
        username: req.params.username
      });
      if (!user) {
        return res.status(StatusCodes.NOT_FOUND).json({ error: 'Not Found' });
      }
      const { username, profilePic, points } = user;

      logger.info(user);
      return res.status(StatusCodes.OK).json({ username, profilePic, points });
    } catch (error) {
      logger.err(error);
      return res
        .status(StatusCodes.INTERNAL_SERVER_ERROR)
        .json({ error: 'Internal Server Error' });
    }
  }

  @Patch('info')
  @Middleware([authenticateToken, upload])
  private async updateUserInfo(req: Request | any, res: Response) {
    const { username, email, password, profilePic, token } = req.body;
    const { file } = req;
    if (
      !validateEmail(email) ||
      !validatePassword(password) ||
      !validateUsername(username)
    ) {
      logger.err({ ...req.body, error: 'Error validating input' });
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ error: 'Invalid field' });
    }

    // Prepare the update object
    const updateData: Partial<UserData> = {};
    if (email) updateData.email = email;
    if (password) updateData.password = await hash(password, config.saltRounds);
    if (file) updateData.profilePic = file.path;

    // Perform the update operation
    try {
      await this.userDataRepository.update(req.user.id, updateData);
      logger.info(updateData);
      return res.status(StatusCodes.OK).json({ message: 'User info updated' });
    } catch (error) {
      logger.err(error);
      return res
        .status(StatusCodes.INTERNAL_SERVER_ERROR)
        .json({ error: 'Internal Server Error' });
    }
  }

  @Post('register')
  private async register(req: Request, res: Response) {
    const { username, password, email } = req.body;

    if (
      !validateUsername(username) ||
      !validatePassword(password) ||
      !validateEmail(email)
    )
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ error: 'Invalid field' });

    const existingUser = await this.userDataRepository.findOneBy({ username });
    if (existingUser) {
      logger.err('Existing username tried to register');
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ error: 'Username already exists' });
    }

    // Hash password
    const hashedPassword = await hash(password, config.saltRounds);

    const newUser = this.userDataRepository.create({
      ...req.body,
      password: hashedPassword
    });

    const savedUser = await this.userDataRepository.save(newUser);
    logger.info(savedUser);
    return res
      .status(StatusCodes.CREATED)
      .json({ message: 'User created successfully' });
  }

  @Post('login')
  private async login(req: Request, res: Response) {
    const { username, password } = req.body;

    if (!validateUsername(username) || !validatePassword(password)) {
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ error: 'Invalid input' });
    }

    const user = await this.userDataRepository.findOneBy({ username });
    if (!user) {
      return res
        .status(StatusCodes.NOT_FOUND)
        .json({ error: 'User not found' });
    }

    const isPasswordMatch = await compare(password, user.password);

    if (!isPasswordMatch) {
      return res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ error: 'Incorrect password' });
    }

    const token = generateToken(user);

    res.cookie('jwt', token, {
      httpOnly: !config.secure,
      secure: config.secure,
      sameSite: config.secure ? 'none' : 'lax',
      maxAge: 36000000
    });

    // Update user with new token and expiration
    await this.userDataRepository.update(user.id, { token });
    logger.info(token);
    return res
      .status(StatusCodes.OK)
      .json({
        message: 'Successfully logged in',
        username: user.username,
        profilePic: user.profilePic
      });
  }

  @Get('logout')
  @Middleware(authenticateToken)
  private async logout(req: Request, res: Response) {
    // const { username, token } = req.body;

    // if (!validateUsername(username)) {
    //   return res.status(StatusCodes.BAD_REQUEST).send('Invalid username');
    // }

    // const user = await this.userDataRepository.findOneBy({ username });
    // if (!user) {
    //   return res.status(StatusCodes.NOT_FOUND).send('User not found');
    // }

    // if (user.token !== token) {
    //   return res.status(StatusCodes.UNAUTHORIZED).send('Invalid token');
    // }

    // res.clearCookie('jwt');
    // // Invalidate the token
    // await this.userDataRepository.update(user.id, {
    //   token: undefined
    // });
    res.clearCookie('jwt');

    logger.info('Logout');
    return res
      .status(StatusCodes.OK)
      .json({ message: 'Logged out successfully' });
  }
  // UserController

  @Get('verify')
  @Middleware(authenticateToken)
  private async verifyUser(req: Request | any, res: Response) {
    try {
      // The middleware has already verified the JWT and set the user in req
      if (req.user) {
        const user =
          await this.userDataRepository.findOneBy({
            id: req.user.id
          });
        if (!user) {
          return res.status(StatusCodes.NOT_FOUND).json({ error: 'User not found' })
        }
        const { username, profilePic } = user;
        return res.status(StatusCodes.OK).json({
          isAuthenticated: true,
          username,
          profilePic
        });
      } else {
        return res
          .status(StatusCodes.UNAUTHORIZED)
          .json({ isAuthenticated: false });
      }
    } catch (error) {
      logger.err(error);
      return res
        .status(StatusCodes.INTERNAL_SERVER_ERROR)
        .json({ error: 'An error occurred' });
    }
  }
}
