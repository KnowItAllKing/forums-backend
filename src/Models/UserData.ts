import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity('userData')
export class UserData {
	@PrimaryGeneratedColumn()
	public id!: string;

	@Column({nullable: true})
	public token?: string;

    @Column({ unique: true })
    public username!: string;

    @Column()
    public password!: string;

    @Column({nullable: true})
    public profilePic?: string;

    @Column()
    public email!: string;

    @Column()
    public points: number = 0;
}