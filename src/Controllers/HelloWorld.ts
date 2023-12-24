import { Controller, Get } from '@overnightjs/core';
import { Request, Response } from 'express';
import { StatusCodes } from 'http-status-codes';

@Controller('app')
export class HelloWorldController {
	@Get('helloworld')
	private helloWorld(req: Request, res: Response) {
		return res.status(StatusCodes.OK).send('Hey boss. How are ya?');
	}
}
