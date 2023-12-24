import { Controller, Get, Post, Delete } from '@overnightjs/core';
import { Request, Response } from 'express';
import { StatusCodes } from 'http-status-codes';
import { DataSource, Repository } from 'typeorm';

import { JwtPayload, verify } from 'jsonwebtoken';

import { UserData, PostData } from '../Models';
import { config } from '../config';
import { logger } from '../';

@Controller('posts')
export class PostController {
  private postRepository: Repository<PostData>;
  private userRepository: Repository<UserData>;

  constructor(dataSource: DataSource) {
    this.postRepository = dataSource.getRepository(PostData);
    this.userRepository = dataSource.getRepository(UserData);
  }

  @Get('')
  private async getAllPosts(req: Request, res: Response) {
    try {
      const posts = await this.postRepository.find();
      const toSend: PostType[] = [];
      for (const post of posts) {
        const user = await this.userRepository.findOneBy({ id: post.authorId });
        if (!user) continue;
        toSend.push({
          ...post,
          username: user.username,
          profilePic: user.profilePic,
          timeCreated: parseInt(post.timeCreated)
        });
      }
      return res.status(StatusCodes.OK).json(toSend);
    } catch (error) {
      return res
        .status(StatusCodes.INTERNAL_SERVER_ERROR)
        .json({ error: 'Error fetching posts' });
    }
  }

  @Get(':id')
  private async getPostById(req: Request, res: Response) {
    const postId = req.params.id;
    const token = req.cookies.jwt;
  
    try {
      const post = await this.postRepository.findOneBy({ id: postId });
      if (!post) {
        return res.status(StatusCodes.NOT_FOUND).json({ error: 'Post not found' });
      }
  
      let isAuthor = false;

      if (token) {
        try {

          const decoded = verify(token, config.secret) as JwtPayload;
          isAuthor = decoded.id == post.authorId;
  
          // Additional logging
        } catch (error) {
          logger.err(`Token decoding error: ${error}`);
        }
      }
  
      const user = await this.userRepository.findOneBy({ id: post.authorId });
      if (!user) {
        return res.status(StatusCodes.NOT_FOUND).json({ error: 'User not found' });
      }
  
      const responseData = {
        ...post,
        username: user.username,
        profilePic: user.profilePic,
        timeCreated: parseInt(post.timeCreated),
        isAuthor
      };
  
      return res.status(StatusCodes.OK).json(responseData);
    } catch (error) {
      return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error: 'Error fetching post' });
    }
  }
  

  @Post('')
  private async createPost(req: Request, res: Response) {
    if (!req.cookies.jwt) {
      return res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ error: 'Unauthorized' });
    }

    const { title, content } = req.body;

    if (!title || !content) {
      return res.status(StatusCodes.BAD_REQUEST).json({ error: 'Bad post' });
    }

    const token = req.cookies.jwt;

    try {
      var decoded = verify(token, config.secret) as JwtPayload;
    } catch (error) {
      return res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ error: 'Invalid token' });
    }

    // Validate the post content
    if (content.length > 500) {
      // Example max length check
      return res
        .status(StatusCodes.BAD_REQUEST)
        .json({ error: 'Post content too long' });
    }

    const newPost = this.postRepository.create({
      title,
      content,
      authorId: decoded.id,
      timeCreated: String(Date.now())
    });
    await this.postRepository.save(newPost);

    return res
      .status(StatusCodes.CREATED)
      .json({ message: 'Post created successfully' });
  }

  @Delete(':id')
  private async deletePost(req: Request, res: Response) {
    const postId = req.params.id;
    const token = req.cookies.jwt;

    if (!token) {
      return res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ error: 'Unauthorized' });
    }

    try {
      var decoded = verify(token, config.secret) as JwtPayload;
    } catch (error) {
      return res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ error: 'Invalid token' });
    }

    const post = await this.postRepository.findOneBy({ id: postId });

    if (!post) {
      return res
        .status(StatusCodes.NOT_FOUND)
        .json({ error: 'Post not found' });
    }

    if (post.authorId != decoded.id) {
      return res
        .status(StatusCodes.FORBIDDEN)
        .json({ error: 'You do not have permission to delete this post' });
    }

    await this.postRepository.remove(post);

    return res
      .status(StatusCodes.OK)
      .json({ message: 'Post deleted successfully' });
  }
}

type PostType = {
  id: string;
  content: string;
  title: string;
  authorId: string;
  timeCreated: number;
  username?: string;
  profilePic?: string;
};
