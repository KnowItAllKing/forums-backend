import { Entity, PrimaryColumn, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity('posts')
export class PostData {

	@PrimaryGeneratedColumn()
    public readonly id!: string;
    
    @Column()
    public content!: string;

    @Column()
    public title!: string;

    @Column()
    public readonly authorId!: string;

    @Column()
    public readonly timeCreated!: string;

}