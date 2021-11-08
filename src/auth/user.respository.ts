import { ConflictException } from "@nestjs/common";
import { EntityRepository, Repository } from "typeorm";
import { AuthCredentialsDto } from "./dto/auth-credential.dto";
import { User } from "./user.entity";
import * as bcrypt from 'bcryptjs';

@EntityRepository(User)
export class UserRepository extends Repository<User> {
    async createUser(authCredentialsDto: AuthCredentialsDto): Promise<void> {
        const {username, password} = authCredentialsDto;
        
        const salt = await bcrypt.genSalt();
        const hasedPassword = await bcrypt.hash(password, salt);

        const user = this.create({username, password: hasedPassword});
        
        try {
            await this.save(user);
        } catch (error) {
            if (error.code === '23305') {
                throw new ConflictException('Existing username');
            } else {
                console.log('error', error);
            }
        }
    }
}