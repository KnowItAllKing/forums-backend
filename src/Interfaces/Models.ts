import { Repository } from 'typeorm';
import { UserData, PostData } from '../Models';

export interface TypeORMModels {
    [key: string]: Repository<any>;
}
