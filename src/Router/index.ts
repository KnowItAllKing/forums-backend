import { Server } from '@overnightjs/core';
import express from 'express';
import { json, urlencoded } from 'body-parser';
import { logger } from '../';
import { StatusCodes } from 'http-status-codes';
import cors, { CorsOptions } from 'cors';
import cp from 'cookie-parser';
import { TypeORMController } from '../Database';
import * as Controllers from '../Controllers';
import { config } from '../config';


// const corsOptions = {
//   credentials: true,
//   origin: (origin: string, callback: any) => {
//     if (!origin || config.allowedOrigins.indexOf(origin) !== -1) {
//       callback(null, true);
//     } else {
//       callback(new Error('Not allowed by CORS'));
//     }
//   }
// }

const corsOptions = { origin: 'http://localhost:3000', credentials: true };

export class Router extends Server {
  public database: TypeORMController = new TypeORMController();

  public constructor() {
    super(false);

    this.app.use(json());
    this.app.use(urlencoded({ extended: true }));
    this.app.use('/uploads', express.static('uploads'));
    this.app.use(cors(corsOptions as CorsOptions));
    this.app.use(cp());

    this.setup();
  }

  private async setup(): Promise<void> {
    await this.database.createConnection();
    this.setupControllers();
    this.start();
  }

  private setupControllers(): void {
    const controllerInstances: any = [];
    for (const name of Object.keys(Controllers)) {
      const controller = (Controllers as any)[name];
      if (typeof controller === 'function') {
        controllerInstances.push(new controller(this.database));
      }
    }
    super.addControllers(controllerInstances);
        
    this.app.use((req, res, next) => {
      logger.err(`404 - Not Found - ${req.originalUrl}`);
      res.status(404).json({ error: 'Not Found' });
    });    
  }

  public async start(): Promise<void> {
    this.app.get('/', (req, res) => {
      res.status(StatusCodes.OK).send('Hello from Stryfe Forums!');
    });

    this.app.listen(config.port, () => {
      logger.info(`Server listening on port ${config.port}`);
    });
  }
}
